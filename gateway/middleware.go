package main

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestTimeoutMiddleware applies a context timeout to the request and aborts
// with 504 if the timeout is exceeded. It attaches the derived context to
// the request so downstream handlers and HTTP calls can use it.
func RequestTimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)

		finished := make(chan struct{}, 1)
		panicChan := make(chan interface{}, 1)

		// Run remaining handlers in a separate goroutine so we can wait on the
		// request context's Done() channel simultaneously.
		go func() {
			defer func() {
				if r := recover(); r != nil {
					panicChan <- r
				}
			}()
			c.Next()
			finished <- struct{}{}
		}()

		select {
		case <-finished:
			// Completed successfully within timeout
			return
		case p := <-panicChan:
			// Re-panic to preserve behavior
			panic(p)
		case <-ctx.Done():
			// Timeout exceeded — respond with 504. The handler goroutine will
			// eventually finish and is not blocked on this select.
			c.AbortWithStatusJSON(504, gin.H{
				"error":   "Gateway Timeout",
				"message": "Request exceeded maximum allowed time",
			})
			return
		}
	}
}
