// Package metrics serves Prometheus metrics from a service that has no HTTP server of its own (a gRPC service, a worker).
// A service builds a registry with its collectors (the Go runtime and the process come with it) and serves it on
// METRICS_ADDR (config.Metrics); Prometheus finds the pod by its annotations (`prometheus.io/scrape`, `/port`, `/path`).
package metrics

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// NewRegistry returns a registry with the Go runtime and process collectors and the collectors given.
func NewRegistry(cs ...prometheus.Collector) *prometheus.Registry {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	r.MustRegister(cs...)
	return r
}

// Handler serves /metrics of the registry.
func Handler(r *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	return mux
}

// Serve serves the registry on addr in the background and returns the function that stops it. An empty addr serves
// nothing (the metrics are turned off). A failure to listen is logged, it does not stop the service.
func Serve(addr string, r *prometheus.Registry, log *zap.Logger) (stop func()) {
	if addr == "" {
		return func() {}
	}
	srv := &http.Server{Addr: addr, Handler: Handler(r), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", zap.Error(err), zap.String("addr", addr))
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}
