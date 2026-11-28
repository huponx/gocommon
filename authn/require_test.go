package authn

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRequireUser(t *testing.T) {
	user := WithPrincipal(context.Background(), &Principal{Subject: "u1", ClientID: "gatekeeper"})
	if got, err := RequireUser(user); err != nil || got != "u1" {
		t.Fatalf("a user: %q %v", got, err)
	}
	for name, ctx := range map[string]context.Context{
		"no principal (a ServiceAccount)": context.Background(),
		"a service token":                 WithPrincipal(context.Background(), &Principal{Subject: "billing", ClientID: "billing"}),
		"no subject":                      WithPrincipal(context.Background(), &Principal{}),
	} {
		if _, err := RequireUser(ctx); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRequirePrincipal(t *testing.T) {
	if _, err := RequirePrincipal(context.Background()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("%v", err)
	}
	p := &Principal{Subject: "billing", ClientID: "billing"}
	if got, err := RequirePrincipal(WithPrincipal(context.Background(), p)); err != nil || got != p {
		t.Fatalf("%v %v", got, err)
	}
}
