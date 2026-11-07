package requestctx

import (
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestHTTPRoundTripOmitsUserID(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HTTPHeaderCorrelationID, "corr-1")
	r.Header.Set("User-ID", "should-ignore")
	v := FromHTTP(r)
	if v.CorrelationID != "corr-1" {
		t.Fatalf("correlation: %q", v.CorrelationID)
	}
	if v.UserID != "" {
		t.Fatalf("user id should not come from HTTP headers, got %q", v.UserID)
	}
	if v.RequestID == "" {
		t.Fatal("expected generated request id")
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	ctx := WithValues(context.Background(), Values{
		CorrelationID: "c",
		UserID:        "u",
	})
	ctx = AppendOutgoing(ctx)
	out, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("missing outgoing metadata")
	}
	incoming := metadata.NewIncomingContext(context.Background(), out)
	got := From(HydrateIncoming(incoming))
	if got.CorrelationID != "c" || got.UserID != "u" {
		t.Fatalf("got %+v", got)
	}
}

func TestAppendOutgoingDoesNotOverwrite(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(MDCorrelationID, "existing"))
	ctx = WithValues(ctx, Values{CorrelationID: "from-ctx", UserID: "u"})
	ctx = AppendOutgoing(ctx)
	md, _ := metadata.FromOutgoingContext(ctx)
	if got := md.Get(MDCorrelationID)[0]; got != "existing" {
		t.Fatalf("overwrote correlation: %q", got)
	}
	if got := md.Get(MDUserID)[0]; got != "u" {
		t.Fatalf("user id: %q", got)
	}
}
