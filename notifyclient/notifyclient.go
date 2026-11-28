// Package notifyclient is how a service sends a notification through courier: it says what happened (an event type of the
// courier catalog and its data) and to whom (users of identity, or raw addresses); courier chooses the channels, the
// address, the language and the template. It wraps the generated gRPC client so that no service builds the protobuf
// Struct or the request by hand.
package notifyclient

import (
	"context"
	"fmt"
	"time"

	"github.com/huponx/gocommon/grpcclient"
	"github.com/huponx/gocommon/tlsconfig"
	courierv1 "github.com/huponx/protogen/go/courier/v1"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
)

// Recipient is a raw address: a person identity does not know, an operations chat.
type Recipient struct {
	Channel courierv1.Channel
	Address string
}

// Request is one event.
type Request struct {
	// EventType is a type of the catalog of courier, for example "security.password_reset". Unknown types are refused.
	EventType string
	// IdempotencyKey makes a repeated call a no-op: the same key returns the first event and sends nothing again.
	IdempotencyKey string
	// UserIDs are users of identity; courier looks up their address, name and language.
	UserIDs []string
	// Recipients are raw addresses, used with or instead of UserIDs.
	Recipients []Recipient
	// Locale is the language of the raw recipients (users have their own).
	Locale string
	// Data are the values of the event, validated by courier against its type.
	Data map[string]string
	// Channels narrows the channels of the type (never widens them); empty: all.
	Channels []string
}

// Result is what courier accepted.
type Result struct {
	EventID string
	// Queued is the number of deliveries created (0 for a repeated IdempotencyKey).
	Queued int
	// SkippedUserIDs got nothing: no e-mail on record, a channel turned off, or no linked Telegram.
	SkippedUserIDs []string
}

// Client sends events to courier.
type Client struct {
	rpc courierv1.CourierServiceClient
}

// New wraps a courier gRPC client.
func New(rpc courierv1.CourierServiceClient) *Client { return &Client{rpc: rpc} }

// Notify sends the event. The error carries the gRPC status of courier (InvalidArgument for a data that does not fit the
// type, Unavailable when identity or the store is down: the caller may retry the same IdempotencyKey).
func (c *Client) Notify(ctx context.Context, r Request) (Result, error) {
	fields := make(map[string]any, len(r.Data))
	for k, v := range r.Data {
		fields[k] = v
	}
	data, err := structpb.NewStruct(fields)
	if err != nil {
		return Result{}, fmt.Errorf("courier %s: %w", r.EventType, err)
	}
	req := &courierv1.NotifyRequest{
		IdempotencyKey: r.IdempotencyKey, EventType: r.EventType, UserIds: r.UserIDs, LocaleOverride: r.Locale, Data: data, Channels: r.Channels,
	}
	for _, rec := range r.Recipients {
		req.Recipients = append(req.Recipients, &courierv1.Recipient{Channel: rec.Channel, Address: rec.Address})
	}
	resp, err := c.rpc.Notify(ctx, req)
	if err != nil {
		return Result{}, fmt.Errorf("courier %s: %w", r.EventType, err)
	}
	return Result{EventID: resp.GetEventId(), Queued: int(resp.GetQueued()), SkippedUserIDs: resp.GetSkippedUserIds()}, nil
}

// DialConfig says how to reach courier.
type DialConfig struct {
	// Target is host:port of courier (gRPC).
	Target string
	// TokenFile is the projected ServiceAccount token (audience courier), re-read when the kubelet rotates it. Empty on a
	// laptop: a local courier does not authenticate services.
	TokenFile string
	Timeout   time.Duration
	// Secure turns TLS on; the default is plaintext gRPC. TLS trusts TLS.CAFile (plus the system roots).
	Secure bool
	TLS    tlsconfig.ClientConfig
	Logger *zap.Logger
}

// Dial connects to courier and returns the client and the function that closes the connection.
func Dial(ctx context.Context, cfg DialConfig) (*Client, func() error, error) {
	opts := []grpcclient.Option{grpcclient.WithLogger(cfg.Logger), grpcclient.WithInsecure(!cfg.Secure)}
	if cfg.Secure {
		opts = append(opts, grpcclient.WithTLSFiles(cfg.TLS))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, grpcclient.WithTimeout(cfg.Timeout))
	}
	if cfg.TokenFile != "" {
		opts = append(opts, grpcclient.WithBearerTokenFile(cfg.TokenFile))
	}
	conn, err := grpcclient.Dial(ctx, cfg.Target, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("dial courier: %w", err)
	}
	return New(courierv1.NewCourierServiceClient(conn)), conn.Close, nil
}
