package tlsconfig

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPClient returns an HTTP client that trusts the system roots plus cfg.CAFile, for the calls between services over
// HTTPS (JWKS, token endpoint, back-channel logout). A target with an http:// URL is unaffected by the config.
func HTTPClient(cfg ClientConfig, timeout time.Duration) (*http.Client, error) {
	tc, err := Client(cfg)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// ServeTLS serves srv on l over HTTPS with the certificate of cfg, reloaded when the files change (see Server). It is the
// second listener of a service whose plaintext port stays for the ingress and the probes: build another http.Server with
// the same handler. It returns http.ErrServerClosed after Shutdown, like Serve.
func ServeTLS(srv *http.Server, l net.Listener, cfg ServerConfig) error {
	tc, err := Server(cfg)
	if err != nil {
		return err
	}
	srv.TLSConfig = tc
	return srv.ServeTLS(l, "", "")
}

// HTTPClientForURL is HTTPClient for a configured URL: nil (the library default client) unless rawURL is https://, so a
// service whose URL is still plain HTTP never reads the CA file, which may not be mounted yet.
func HTTPClientForURL(rawURL string, cfg ClientConfig, timeout time.Duration) (*http.Client, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return nil, nil
	}
	return HTTPClient(cfg, timeout)
}
