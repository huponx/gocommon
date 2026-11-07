package logging

import (
	"context"
	"os"

	"github.com/huponx/gocommon/requestctx"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey struct{}

type Config struct {
	Level    string
	Encoding string
	Service  string
	Env      string
}

func New(cfg Config) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if cfg.Level != "" {
		if err := level.Set(cfg.Level); err != nil {
			return nil, err
		}
	}

	encoding := cfg.Encoding
	if encoding == "" {
		encoding = "console"
	}

	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	if encoding == "console" {
		encCfg = zap.NewDevelopmentEncoderConfig()
		encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	var enc zapcore.Encoder
	if encoding == "json" {
		enc = zapcore.NewJSONEncoder(encCfg)
	} else {
		enc = zapcore.NewConsoleEncoder(encCfg)
	}

	core := zapcore.NewCore(enc, zapcore.AddSync(os.Stdout), level)
	log := zap.New(core, zap.AddCaller())
	fields := []zap.Field{}
	if cfg.Service != "" {
		fields = append(fields, zap.String("service", cfg.Service))
	}
	if cfg.Env != "" {
		fields = append(fields, zap.String("env", cfg.Env))
	}
	if len(fields) > 0 {
		log = log.With(fields...)
	}
	return log, nil
}

func WithCtx(ctx context.Context, log *zap.Logger) context.Context {
	if log == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, log)
}

func FromCtx(ctx context.Context) *zap.Logger {
	if ctx != nil {
		if log, ok := ctx.Value(ctxKey{}).(*zap.Logger); ok && log != nil {
			return withRequestFields(log, requestctx.From(ctx))
		}
	}
	return withRequestFields(zap.NewNop(), requestctx.From(ctx))
}

func Sync(log *zap.Logger) {
	if log == nil {
		return
	}
	_ = log.Sync()
}

func withRequestFields(log *zap.Logger, v requestctx.Values) *zap.Logger {
	if log == nil {
		log = zap.NewNop()
	}
	fields := make([]zap.Field, 0, 4)
	if v.CorrelationID != "" {
		fields = append(fields, zap.String("correlation_id", v.CorrelationID))
	}
	if v.UserID != "" {
		fields = append(fields, zap.String("user_id", v.UserID))
	}
	if v.RequestID != "" {
		fields = append(fields, zap.String("request_id", v.RequestID))
	}
	if v.TenantID != "" {
		fields = append(fields, zap.String("tenant_id", v.TenantID))
	}
	if len(fields) == 0 {
		return log
	}
	return log.With(fields...)
}
