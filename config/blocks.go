package config

import (
	"fmt"
	"net/url"
	"time"
)

type Server struct {
	Host            string        `env:"HOST" envDefault:"0.0.0.0"`
	Port            int           `env:"PORT" envDefault:"8080"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`
}

func (s Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

type Log struct {
	Level    string `env:"LOG_LEVEL" envDefault:"info"`
	Encoding string `env:"LOG_ENCODING" envDefault:"console"`
	Service  string `env:"SERVICE_NAME" envDefault:"app"`
	Env      string `env:"ENV" envDefault:"dev"`
}

type Postgres struct {
	Host     string `env:"POSTGRES_HOST" envDefault:"localhost"`
	Port     int    `env:"POSTGRES_PORT" envDefault:"5432"`
	User     string `env:"POSTGRES_USER" envDefault:"postgres"`
	Password string `env:"POSTGRES_PASSWORD"`
	Database string `env:"POSTGRES_DB" envDefault:"app"`
	SSLMode  string `env:"POSTGRES_SSLMODE" envDefault:"disable"`
}

func (p Postgres) URL() string {
	u := &url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", p.Host, p.Port),
		Path:   p.Database,
	}
	if p.User != "" {
		u.User = url.UserPassword(p.User, p.Password)
	}
	q := u.Query()
	if p.SSLMode != "" {
		q.Set("sslmode", p.SSLMode)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Metrics is where a service without an HTTP server serves its Prometheus metrics (package metrics). Empty turns them off.
type Metrics struct {
	MetricsAddr string `env:"METRICS_ADDR" envDefault:":9100"`
}

type Redis struct {
	Host     string `env:"REDIS_HOST" envDefault:"localhost"`
	Port     int    `env:"REDIS_PORT" envDefault:"6379"`
	Password string `env:"REDIS_PASSWORD"`
	DB       int    `env:"REDIS_DB" envDefault:"0"`
}

func (r Redis) URL() string {
	u := &url.URL{
		Scheme: "redis",
		Host:   fmt.Sprintf("%s:%d", r.Host, r.Port),
		Path:   fmt.Sprintf("%d", r.DB),
	}
	if r.Password != "" {
		u.User = url.UserPassword("", r.Password)
	}
	return u.String()
}

type GRPCClient struct {
	Target   string        `env:"GRPC_TARGET" envDefault:"localhost:9090"`
	Timeout  time.Duration `env:"GRPC_TIMEOUT" envDefault:"5s"`
	Insecure bool          `env:"GRPC_INSECURE" envDefault:"true"`
}
