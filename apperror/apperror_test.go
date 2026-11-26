package apperror

import (
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFromGRPCStatus(t *testing.T) {
	err := status.Error(codes.Unavailable, "downstream down")
	got := From(err)
	if got.Code != codes.Unavailable {
		t.Fatalf("code: %v", got.Code)
	}
	if HTTPStatus(err) != http.StatusBadGateway {
		t.Fatalf("http: %d", HTTPStatus(err))
	}
}

func TestFromAppError(t *testing.T) {
	err := NotFound("user missing")
	if HTTPStatus(err) != http.StatusNotFound {
		t.Fatalf("http: %d", HTTPStatus(err))
	}
	st := status.Convert(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("grpc: %v", st.Code())
	}
}

func TestReasonRoundTrip(t *testing.T) {
	err := FailedPrecondition("this is the last admin").WithReason("last_admin", "role", "admin", "dangling")
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition || st.Message() != "this is the last admin" {
		t.Fatalf("status: %v %q", st.Code(), st.Message())
	}
	// as a client sees it: only the status travelled
	got := From(status.Error(st.Code(), st.Message()))
	if got.Reason != "" {
		t.Fatalf("reason without details: %q", got.Reason)
	}
	got = From(st.Err())
	if got.Reason != "last_admin" || got.Params["role"] != "admin" || len(got.Params) != 1 {
		t.Fatalf("reason: %q %v", got.Reason, got.Params)
	}
	if got.Message != "this is the last admin" {
		t.Fatalf("message: %q", got.Message)
	}
}

func TestWithReasonKeepsPlainErrorsPlain(t *testing.T) {
	if st := status.Convert(NotFound("x")); len(st.Details()) != 0 {
		t.Fatalf("details: %v", st.Details())
	}
	var nilErr *Error
	if nilErr.WithReason("x") != nil {
		t.Fatal("nil error")
	}
}
