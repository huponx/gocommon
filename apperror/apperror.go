package apperror

import (
	"errors"
	"net/http"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Domain is the ErrorInfo domain of the reasons of this package.
const Domain = "apperror"

type Error struct {
	Code    codes.Code
	Message string
	// Reason is a stable snake_case key of the error ("last_admin"); a client translates it. Optional.
	Reason string
	// Params fill the placeholders of the translated reason ({"limit": "256 MiB"}). Optional.
	Params map[string]string
	err    error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.err != nil {
		return e.err.Error()
	}
	return e.Code.String()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *Error) GRPCStatus() *status.Status {
	if e == nil {
		return status.New(codes.OK, "")
	}
	st := status.New(e.Code, e.Error())
	if e.Reason == "" {
		return st
	}
	withInfo, err := st.WithDetails(&errdetails.ErrorInfo{Reason: e.Reason, Domain: Domain, Metadata: e.Params})
	if err != nil {
		return st
	}
	return withInfo
}

// WithReason sets the stable reason and its parameters, given as key, value pairs; it returns e for chaining.
// A trailing key without a value is ignored.
func (e *Error) WithReason(reason string, params ...string) *Error {
	if e == nil {
		return nil
	}
	e.Reason = reason
	e.Params = nil
	for i := 0; i+1 < len(params); i += 2 {
		if e.Params == nil {
			e.Params = make(map[string]string, len(params)/2)
		}
		e.Params[params[i]] = params[i+1]
	}
	return e
}

// ReasonOf returns the reason and parameters carried by the ErrorInfo detail of a gRPC status.
func ReasonOf(st *status.Status) (string, map[string]string) {
	if st == nil {
		return "", nil
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == Domain {
			return info.GetReason(), info.GetMetadata()
		}
	}
	return "", nil
}

func (e *Error) CodeName() string {
	if e == nil {
		return codes.OK.String()
	}
	return e.Code.String()
}

func (e *Error) HTTPStatus() int {
	if e == nil {
		return http.StatusOK
	}
	return httpStatus(e.Code)
}

func newError(code codes.Code, msg string) *Error {
	return &Error{Code: code, Message: msg}
}

func InvalidArgument(msg string) *Error    { return newError(codes.InvalidArgument, msg) }
func NotFound(msg string) *Error           { return newError(codes.NotFound, msg) }
func Unauthenticated(msg string) *Error    { return newError(codes.Unauthenticated, msg) }
func PermissionDenied(msg string) *Error   { return newError(codes.PermissionDenied, msg) }
func AlreadyExists(msg string) *Error      { return newError(codes.AlreadyExists, msg) }
func FailedPrecondition(msg string) *Error { return newError(codes.FailedPrecondition, msg) }
func Unavailable(msg string) *Error        { return newError(codes.Unavailable, msg) }
func Internal(msg string) *Error           { return newError(codes.Internal, msg) }

func Wrap(code codes.Code, msg string, err error) *Error {
	return &Error{Code: code, Message: msg, err: err}
}

func From(err error) *Error {
	if err == nil {
		return nil
	}
	var app *Error
	if errors.As(err, &app) {
		return app
	}
	st, ok := status.FromError(err)
	if !ok {
		return Wrap(codes.Internal, err.Error(), err)
	}
	reason, params := ReasonOf(st)
	return &Error{Code: st.Code(), Message: st.Message(), Reason: reason, Params: params, err: err}
}

func HTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	return From(err).HTTPStatus()
}

func httpStatus(code codes.Code) int {
	switch code {
	case codes.OK:
		return http.StatusOK
	case codes.InvalidArgument, codes.OutOfRange:
		return http.StatusBadRequest
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.NotFound:
		return http.StatusNotFound
	case codes.AlreadyExists, codes.Aborted:
		return http.StatusConflict
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.Unimplemented:
		return http.StatusNotImplemented
	case codes.Unavailable:
		return http.StatusBadGateway
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout
	case codes.Canceled:
		return 499
	default:
		return http.StatusInternalServerError
	}
}
