// Package tlsconfig builds the crypto/tls configs of in-cluster gRPC: servers serve a certificate read from files
// (cert-manager renews the Secret in place, the new certificate is picked up without a restart); clients trust a private CA
// read from a file. Server-side TLS only: a client certificate is never requested.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// ServerConfig is the certificate a server presents.
type ServerConfig struct {
	CertFile string
	KeyFile  string
}

// ClientConfig is what a client trusts. The zero value means the system roots.
type ClientConfig struct {
	// CAFile is a PEM bundle added to the system roots.
	CAFile string
	// ServerName overrides the name the certificate is checked against (default: the host of the target).
	ServerName string
}

// Enabled reports whether a server certificate is configured.
func (c ServerConfig) Enabled() bool { return c.CertFile != "" }

// Server returns a config whose GetCertificate reloads CertFile/KeyFile when either file's modification time changes.
func Server(cfg ServerConfig) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("tls: cert file and key file are both required")
	}
	r := &reloader{cfg: cfg}
	if _, err := r.get(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.get() },
	}, nil
}

// Client returns a config trusting the system roots plus CAFile.
func Client(cfg ClientConfig) (*tls.Config, error) {
	out := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.CAFile == "" {
		return out, nil
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: no certificate in CA file %s", cfg.CAFile)
	}
	out.RootCAs = pool
	return out, nil
}

type reloader struct {
	cfg ServerConfig

	mu       sync.Mutex
	cert     *tls.Certificate
	certTime time.Time
	keyTime  time.Time
}

func (r *reloader) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ci, err := os.Stat(r.cfg.CertFile)
	if err != nil {
		return r.fallback(err)
	}
	ki, err := os.Stat(r.cfg.KeyFile)
	if err != nil {
		return r.fallback(err)
	}
	if r.cert != nil && ci.ModTime().Equal(r.certTime) && ki.ModTime().Equal(r.keyTime) {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
	if err != nil {
		// The kubelet swaps the two files one after the other: keep serving the old pair until they match again.
		return r.fallback(err)
	}
	r.cert, r.certTime, r.keyTime = &cert, ci.ModTime(), ki.ModTime()
	return r.cert, nil
}

func (r *reloader) fallback(err error) (*tls.Certificate, error) {
	if r.cert != nil {
		return r.cert, nil
	}
	return nil, fmt.Errorf("tls: load certificate: %w", err)
}
