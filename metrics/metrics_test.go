package metrics

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func TestRegistryServesItsCollectorsAndTheRuntime(t *testing.T) {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "app_things_total", Help: "things"})
	c.Add(3)
	rec := httptest.NewRecorder()
	Handler(NewRegistry(c)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{"app_things_total 3", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestServeAnswersAndStops(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	stop := Serve(addr, NewRegistry(), zap.NewNop())
	defer stop()
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		if resp, err = http.Get("http://" + addr + "/metrics"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "go_goroutines") {
		t.Fatalf("%d", resp.StatusCode)
	}
	stop()
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Fatal("still serving after stop")
	}
	Serve("", NewRegistry(), zap.NewNop())() // an empty address is a no-op
}
