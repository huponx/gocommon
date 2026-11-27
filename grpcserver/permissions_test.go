package grpcserver

import (
	"strings"
	"testing"

	authzv1 "github.com/huponx/protogen/go/authz/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func method(name string, r *authzv1.Rule) *descriptorpb.MethodDescriptorProto {
	m := &descriptorpb.MethodDescriptorProto{Name: proto.String(name), InputType: proto.String(".bill.v1.Msg"), OutputType: proto.String(".bill.v1.Msg")}
	if r != nil {
		m.Options = &descriptorpb.MethodOptions{}
		proto.SetExtension(m.Options, authzv1.E_Rule, r)
	}
	return m
}

func testFile(t *testing.T, names []string, methods ...*descriptorpb.MethodDescriptorProto) protoreflect.FileDescriptor {
	t.Helper()
	set := &authzv1.PermissionSet{}
	for _, n := range names {
		set.Permissions = append(set.Permissions, &authzv1.PermissionDef{Name: n, Description: "d"})
	}
	opts := &descriptorpb.FileOptions{}
	proto.SetExtension(opts, authzv1.E_Permissions, set)
	fdp := &descriptorpb.FileDescriptorProto{
		Name: proto.String("bill/v1/bill.proto"), Package: proto.String("bill.v1"), Syntax: proto.String("proto3"),
		Options:     opts,
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Msg")}},
		Service:     []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Bill"), Method: methods}},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestPermissionsFromProto(t *testing.T) {
	fd := testFile(t, []string{"bill:invoice:read", "bill:invoice:approve"},
		method("Get", &authzv1.Rule{AnyOf: []string{"bill:invoice:read"}}),
		method("List", &authzv1.Rule{AnyOf: []string{"bill:invoice:read", "bill:invoice:approve"}}),
		method("Close", &authzv1.Rule{AllOf: []string{"bill:invoice:read", "bill:invoice:approve"}}),
		method("Me", &authzv1.Rule{Public: true}),
		method("Both", &authzv1.Rule{Public: true, AnyOf: []string{"bill:invoice:read"}}),
		method("None", nil),
	)
	got := PermissionsFromProto(fd)
	if len(got) != 4 {
		t.Fatalf("got %v", got)
	}
	if r := got["/bill.v1.Bill/List"]; len(r.Any) != 2 || r.Public {
		t.Errorf("List: %+v", r)
	}
	if r := got["/bill.v1.Bill/Close"]; len(r.All) != 2 {
		t.Errorf("Close: %+v", r)
	}
	if !got["/bill.v1.Bill/Me"].Public {
		t.Error("Me must be public")
	}
	if _, ok := got["/bill.v1.Bill/Both"]; ok {
		t.Error("a method with several of any_of/all_of/public stays closed")
	}
	if d := DeclaredPermissions(fd); len(d) != 2 || d[0].Name != "bill:invoice:read" {
		t.Errorf("declared %v", d)
	}
}

func TestRuleAllows(t *testing.T) {
	any2 := Rule{Any: []string{"a:b:read", "a:b:approve"}}
	all2 := Rule{All: []string{"a:b:read", "a:b:approve"}}
	cases := []struct {
		r     Rule
		perms []string
		want  bool
	}{
		{any2, []string{"a:b:approve"}, true},
		{any2, []string{"a:b:write"}, false},
		{all2, []string{"a:b:read"}, false},
		{all2, []string{"a:b:read", "a:b:approve"}, true},
		{all2, []string{"a:*"}, true},
		{Rule{}, []string{"*"}, false},
		{PublicRule, nil, true},
	}
	for i, c := range cases {
		if got := c.r.Allows(c.perms); got != c.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
}

func TestCoverageProblems(t *testing.T) {
	ok := testFile(t, []string{"bill:invoice:read"}, method("Get", &authzv1.Rule{AnyOf: []string{"bill:invoice:read"}}))
	if p := CoverageProblems(ok); len(p) != 0 {
		t.Fatalf("clean file: %v", p)
	}
	bad := testFile(t, []string{"bill:invoice:read", "bill:invoice:read", "other:x:y", "bill:*:read", "bill:read"},
		method("NoRule", nil),
		method("Undeclared", &authzv1.Rule{AnyOf: []string{"bill:invoice:write"}}),
		method("Many", &authzv1.Rule{Public: true, AllOf: []string{"bill:invoice:read"}}),
	)
	joined := strings.Join(CoverageProblems(bad), "\n")
	for _, want := range []string{"declared twice", `"other:x:y" is outside`, `"bill:*:read" is not a valid concrete`, "must be service:resource:action", "NoRule needs exactly one", `Undeclared names "bill:invoice:write"`, "Many needs exactly one"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem %q in:\n%s", want, joined)
		}
	}
}
