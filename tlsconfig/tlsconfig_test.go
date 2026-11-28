package tlsconfig_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huponx/gocommon/grpcclient"
	"github.com/huponx/gocommon/grpcserver"
	"github.com/huponx/gocommon/tlsconfig"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue writes a leaf for name signed by c and returns its PEM cert and key.
func (c *ca) issue(t *testing.T, name string, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type fixture struct {
	dir      string
	ca       *ca
	certFile string
	keyFile  string
	caFile   string
	addr     string
}

// start serves health over TLS with a leaf for "localhost" signed by a fresh CA.
func start(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir(), ca: newCA(t, "test-ca")}
	f.certFile, f.keyFile, f.caFile = filepath.Join(f.dir, "tls.crt"), filepath.Join(f.dir, "tls.key"), filepath.Join(f.dir, "ca.crt")
	c, k := f.ca.issue(t, "localhost", 10)
	write(t, f.certFile, c)
	write(t, f.keyFile, k)
	write(t, f.caFile, f.ca.pem)

	cfg, err := tlsconfig.Server(tlsconfig.ServerConfig{CertFile: f.certFile, KeyFile: f.keyFile})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpcserver.New(grpcserver.WithTLS(cfg))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.GRPC.Serve(lis) }()
	t.Cleanup(srv.GRPC.Stop)
	// Dialed by name: the leaf has a DNS SAN only.
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	f.addr = net.JoinHostPort("localhost", port)
	return f
}

func check(t *testing.T, addr string, opts ...grpcclient.Option) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpcclient.Dial(ctx, addr, append(opts, grpcclient.WithTimeout(2*time.Second))...)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestServerTLSWithClientCA(t *testing.T) {
	f := start(t)
	if err := check(t, f.addr, grpcclient.WithTLSFiles(tlsconfig.ClientConfig{CAFile: f.caFile})); err != nil {
		t.Fatalf("want ok, got %v", err)
	}
}

func TestWrongCAFails(t *testing.T) {
	f := start(t)
	other := filepath.Join(f.dir, "other.crt")
	write(t, other, newCA(t, "other-ca").pem)
	err := check(t, f.addr, grpcclient.WithTLSFiles(tlsconfig.ClientConfig{CAFile: other}))
	if err == nil || !untrusted(err) {
		t.Fatalf("want an untrusted certificate error, got %v", err)
	}
}

func TestSystemRootsDoNotTrustPrivateCA(t *testing.T) {
	f := start(t)
	err := check(t, f.addr, grpcclient.WithInsecure(false))
	if err == nil || !untrusted(err) {
		t.Fatalf("want an untrusted certificate error, got %v", err)
	}
}

func TestWrongServerNameFails(t *testing.T) {
	f := start(t)
	err := check(t, f.addr, grpcclient.WithTLSFiles(tlsconfig.ClientConfig{CAFile: f.caFile, ServerName: "other.svc"}))
	if err == nil || !strings.Contains(err.Error(), "other.svc") {
		t.Fatalf("want a certificate name error, got %v", err)
	}
}

func TestPlaintextClientAgainstTLSServerFails(t *testing.T) {
	f := start(t)
	if err := check(t, f.addr); err == nil {
		t.Fatal("want an error")
	}
}

func TestTLSClientAgainstPlaintextServerFails(t *testing.T) {
	srv := grpcserver.New()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.GRPC.Serve(lis) }()
	t.Cleanup(srv.GRPC.Stop)
	f := &fixture{dir: t.TempDir(), ca: newCA(t, "ca")}
	f.caFile = filepath.Join(f.dir, "ca.crt")
	write(t, f.caFile, f.ca.pem)
	err = check(t, lis.Addr().String(), grpcclient.WithTLSFiles(tlsconfig.ClientConfig{CAFile: f.caFile}))
	if err == nil {
		t.Fatal("want an error")
	}
}

// A renewed certificate (same files, new content) is served to new connections without restarting the server.
func TestCertificateRotation(t *testing.T) {
	f := start(t)
	tlsOpt := grpcclient.WithTLSFiles(tlsconfig.ClientConfig{CAFile: f.caFile})

	serial := func() int64 {
		cfg, _ := tlsconfig.Client(tlsconfig.ClientConfig{CAFile: f.caFile})
		conn, err := tlsDial(f.addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	if err := check(t, f.addr, tlsOpt); err != nil {
		t.Fatal(err)
	}
	if got := serial(); got != 10 {
		t.Fatalf("serial %d", got)
	}

	c, k := f.ca.issue(t, "localhost", 11)
	future := time.Now().Add(time.Minute)
	write(t, f.keyFile, k)
	write(t, f.certFile, c)
	for _, p := range []string{f.certFile, f.keyFile} {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
	}
	if got := serial(); got != 11 {
		t.Fatalf("after rotation serial %d, want 11", got)
	}
	if err := check(t, f.addr, tlsOpt); err != nil {
		t.Fatal(err)
	}
}

func TestServerNeedsCertAndKey(t *testing.T) {
	if _, err := tlsconfig.Server(tlsconfig.ServerConfig{CertFile: "x"}); err == nil {
		t.Fatal("want an error")
	}
	if _, err := tlsconfig.Server(tlsconfig.ServerConfig{CertFile: "/nope", KeyFile: "/nope"}); err == nil {
		t.Fatal("want an error")
	}
}

func TestClientBadCAFile(t *testing.T) {
	if _, err := tlsconfig.Client(tlsconfig.ClientConfig{CAFile: "/nope"}); err == nil {
		t.Fatal("want an error")
	}
	bad := filepath.Join(t.TempDir(), "bad.crt")
	write(t, bad, []byte("not pem"))
	if _, err := tlsconfig.Client(tlsconfig.ClientConfig{CAFile: bad}); err == nil {
		t.Fatal("want an error")
	}
	if err := check(t, "127.0.0.1:1", grpcclient.WithTLSFiles(tlsconfig.ClientConfig{CAFile: "/nope"})); err == nil {
		t.Fatal("Dial must report a bad CA file")
	}
}

func tlsDial(addr string, cfg *tls.Config) (*tls.Conn, error) {
	cfg.ServerName = "localhost"
	return tls.Dial("tcp", addr, cfg)
}

// Go reports "unknown authority", the macOS verifier "is not trusted".
func untrusted(err error) bool {
	return strings.Contains(err.Error(), "unknown authority") || strings.Contains(err.Error(), "not trusted")
}
