package notifyclient

import (
	"context"
	"errors"
	"testing"

	courierv1 "github.com/huponx/protogen/go/courier/v1"
	"google.golang.org/grpc"
)

type fake struct {
	courierv1.CourierServiceClient
	got *courierv1.NotifyRequest
	err error
}

func (f *fake) Notify(_ context.Context, in *courierv1.NotifyRequest, _ ...grpc.CallOption) (*courierv1.NotifyResponse, error) {
	f.got = in
	return &courierv1.NotifyResponse{EventId: "e1", Queued: 2, SkippedUserIds: []string{"u9"}}, f.err
}

func TestNotifyBuildsTheRequestAndReadsTheAnswer(t *testing.T) {
	f := &fake{}
	res, err := New(f).Notify(context.Background(), Request{
		EventType: "security.mfa_changed", IdempotencyKey: "k1", UserIDs: []string{"u1", "u9"}, Locale: "vi",
		Data: map[string]string{"change": "enabled"}, Channels: []string{"email"},
		Recipients: []Recipient{{Channel: courierv1.Channel_CHANNEL_EMAIL, Address: "a@x.io"}},
	})
	if err != nil || res.EventID != "e1" || res.Queued != 2 || len(res.SkippedUserIDs) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	g := f.got
	if g.GetEventType() != "security.mfa_changed" || g.GetIdempotencyKey() != "k1" || len(g.GetUserIds()) != 2 || g.GetLocaleOverride() != "vi" ||
		g.GetData().AsMap()["change"] != "enabled" || len(g.GetChannels()) != 1 || g.GetRecipients()[0].GetAddress() != "a@x.io" {
		t.Fatalf("request: %v", g)
	}
}

func TestNotifyWrapsTheError(t *testing.T) {
	boom := errors.New("unavailable")
	_, err := New(&fake{err: boom}).Notify(context.Background(), Request{EventType: "x.y"})
	if !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
}
