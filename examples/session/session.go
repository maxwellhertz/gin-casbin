package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	gcasbin "github.com/maxwellhertz/gin-casbin"
)

func main() {
	r := gin.Default()

	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("subject", store))

	r.POST("/login", func(c *gin.Context) {
		// Verify username and password.
		// ...

		// Store current subject in session
		// and send back session ID.
		session := sessions.Default(c)
		sessionId := uuid.New().String()
		session.Set(sessionId, "alice")
		session.Save()

		c.SetCookie("SESSIONID", sessionId, 3600,"/", "localhost", false, true)
	})

	// Use Casbin authentication middleware.
	auth := gcasbin.NewAuthMiddleware("examples/config/model.conf", "examples/config/policy.csv", subjectFromSession)
	r.GET("/book", auth.Enforce("book", "read"), func(c *gin.Context) {
		c.String(200, "you read the book successfully")
	})

	r.Run()
}

func subjectFromSession(c *gin.Context, _ ...interface{}) interface{} {
	// Get session ID from cookie.
	sessionId, err := c.Cookie("SESSIONID")
	if err != nil {
		// Cookie not found.
		return nil
	}

	// Get subject from session.
	session := sessions.Default(c)
	return session.Get(sessionId)
}
