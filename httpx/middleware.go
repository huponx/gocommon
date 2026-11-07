package httpx

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/gocommon/requestctx"
	"go.uber.org/zap"
)

func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if log == nil {
			c.Next()
			return
		}
		ctx := logging.WithCtx(c.Request.Context(), log)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func RequestContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		v := requestctx.FromHTTP(c.Request)
		ctx := requestctx.WithValues(c.Request.Context(), v)
		c.Request = c.Request.WithContext(ctx)
		c.Header(requestctx.HTTPHeaderCorrelationID, v.CorrelationID)
		c.Next()
	}
}

func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logging.FromCtx(c.Request.Context()).Info("http request",
			zap.String("http.method", c.Request.Method),
			zap.String("http.path", c.Request.URL.Path),
			zap.Int("http.status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
		)
	}
}
