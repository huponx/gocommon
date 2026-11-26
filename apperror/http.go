package apperror

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Payload struct {
	Code    string            `json:"code"`
	Reason  string            `json:"reason,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
	Message string            `json:"message"`
}

type Body struct {
	Error Payload `json:"error"`
}

func WriteHTTP(c *gin.Context, err error) {
	if err == nil {
		c.Status(http.StatusOK)
		return
	}
	e := From(err)
	c.JSON(e.HTTPStatus(), Body{
		Error: Payload{
			Code:    e.CodeName(),
			Reason:  e.Reason,
			Params:  e.Params,
			Message: e.Error(),
		},
	})
}
