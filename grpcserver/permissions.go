package grpcserver

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/huponx/gocommon/authz"
	authzv1 "github.com/huponx/protogen/go/authz/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Declared is a permission a service declares in its permissions.proto.
type Declared struct {
	Name        string
	Description string
	RenamedFrom string
}

// DeclaredPermissions lists the permissions of the `authz.v1.permissions` file option of the files, in file order.
func DeclaredPermissions(files ...protoreflect.FileDescriptor) []Declared {
	var out []Declared
	for _, fd := range files {
		opts, ok := fd.Options().(*descriptorpb.FileOptions)
		if !ok || opts == nil || !proto.HasExtension(opts, authzv1.E_Permissions) {
			continue
		}
		set, _ := proto.GetExtension(opts, authzv1.E_Permissions).(*authzv1.PermissionSet)
		for _, d := range set.GetPermissions() {
			out = append(out, Declared{Name: d.GetName(), Description: d.GetDescription(), RenamedFrom: d.GetRenamedFrom()})
		}
	}
	return out
}

// RuleOf reads the `authz.v1.rule` option of a method. ok is false when the method has none or when it sets more
// than one of any_of, all_of and public (such a method stays closed).
func RuleOf(md protoreflect.MethodDescriptor) (rule Rule, ok bool) {
	opts, isOpts := md.Options().(*descriptorpb.MethodOptions)
	if !isOpts || opts == nil || !proto.HasExtension(opts, authzv1.E_Rule) {
		return Rule{}, false
	}
	r, _ := proto.GetExtension(opts, authzv1.E_Rule).(*authzv1.Rule)
	n := 0
	if len(r.GetAnyOf()) > 0 {
		n++
	}
	if len(r.GetAllOf()) > 0 {
		n++
	}
	if r.GetPublic() {
		n++
	}
	if n != 1 {
		return Rule{}, false
	}
	return Rule{Any: append([]string(nil), r.GetAnyOf()...), All: append([]string(nil), r.GetAllOf()...), Public: r.GetPublic()}, true
}

// PermissionsFromProto builds the method map of WithMethodPermissions from the `authz.v1.rule` options of every RPC
// of the files ("/identity.v1.IdentityService/GetUser" -> Rule). A method without a valid rule is left out, so it
// stays closed (CheckCoverage fails the build of the service for it).
func PermissionsFromProto(files ...protoreflect.FileDescriptor) map[string]Rule {
	out := map[string]Rule{}
	for _, fd := range files {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			sd := svcs.Get(i)
			for j := 0; j < sd.Methods().Len(); j++ {
				md := sd.Methods().Get(j)
				if r, ok := RuleOf(md); ok {
					out["/"+string(sd.FullName())+"/"+string(md.Name())] = r
				}
			}
		}
	}
	return out
}

// CheckCoverage is the test every service runs over its proto files (the service file and its permissions.proto):
//   - every RPC sets exactly one of any_of, all_of and public;
//   - every name in a rule is declared in the permissions of the files;
//   - every declared name is valid, concrete (no wildcard), and starts with the service namespace (the first
//     segment of the proto package, "identity" for identity.v1), and is declared once.
func CheckCoverage(t testing.TB, files ...protoreflect.FileDescriptor) {
	t.Helper()
	for _, msg := range CoverageProblems(files...) {
		t.Error(msg)
	}
}

// CoverageProblems is CheckCoverage as a list of messages, empty when everything is covered.
func CoverageProblems(files ...protoreflect.FileDescriptor) []string {
	var problems []string
	declared := map[string]bool{}
	for _, fd := range files {
		ns, _, _ := strings.Cut(string(fd.Package()), ".")
		for _, d := range DeclaredPermissions(fd) {
			switch {
			case !authz.Valid(d.Name) || strings.Contains(d.Name, "*"):
				problems = append(problems, fmt.Sprintf("permission %q is not a valid concrete name", d.Name))
			case !strings.HasPrefix(d.Name, ns+":"):
				problems = append(problems, fmt.Sprintf("permission %q is outside the namespace %q", d.Name, ns+":"))
			case strings.Count(d.Name, ":") < 2:
				problems = append(problems, fmt.Sprintf("permission %q must be service:resource:action", d.Name))
			case declared[d.Name]:
				problems = append(problems, fmt.Sprintf("permission %q is declared twice", d.Name))
			}
			if d.RenamedFrom != "" && !strings.HasPrefix(d.RenamedFrom, ns+":") {
				problems = append(problems, fmt.Sprintf("renamed_from %q of %q is outside the namespace %q", d.RenamedFrom, d.Name, ns+":"))
			}
			declared[d.Name] = true
		}
	}
	for _, fd := range files {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			sd := svcs.Get(i)
			for j := 0; j < sd.Methods().Len(); j++ {
				md := sd.Methods().Get(j)
				full := "/" + string(sd.FullName()) + "/" + string(md.Name())
				r, ok := RuleOf(md)
				if !ok {
					problems = append(problems, full+" needs exactly one of any_of, all_of and public in its authz.v1.rule option")
					continue
				}
				for _, name := range append(append([]string(nil), r.Any...), r.All...) {
					if !declared[name] {
						problems = append(problems, fmt.Sprintf("%s names %q, which is not declared in permissions.proto", full, name))
					}
				}
			}
		}
	}
	sort.Strings(problems)
	return problems
}
