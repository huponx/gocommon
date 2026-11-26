package grpcclient

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestAppendBearer(t *testing.T) {
	ctx := appendBearer(context.Background(), "tok")
	md, _ := metadata.FromOutgoingContext(ctx)
	got := md.Get(mdAuthorization)
	if len(got) != 1 || got[0] != "Bearer tok" {
		t.Fatalf("%v", got)
	}
}

func TestAppendBearerDoesNotOverwrite(t *testing.T) {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(mdAuthorization, "Bearer existing"))
	ctx = appendBearer(ctx, "tok")
	md, _ := metadata.FromOutgoingContext(ctx)
	if got := md.Get(mdAuthorization); len(got) != 1 || got[0] != "Bearer existing" {
		t.Fatalf("%v", got)
	}
}

func TestAppendBearerEmpty(t *testing.T) {
	ctx := appendBearer(context.Background(), "")
	_, ok := metadata.FromOutgoingContext(ctx)
	if ok {
		t.Fatal("expected no metadata")
	}
}

func TestWithMaxMsgSizeKeepsTheDefaultOfADirectionWithZero(t *testing.T) {
	o := defaultOptions()
	WithMaxMsgSize(16<<20, 0)(&o)
	if o.maxRecvMsgSize != 16<<20 || o.maxSendMsgSize != 8<<20 {
		t.Errorf("recv %d send %d", o.maxRecvMsgSize, o.maxSendMsgSize)
	}
}
