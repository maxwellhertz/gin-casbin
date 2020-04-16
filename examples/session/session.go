package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/maxwellhertz/gin-casbin"
	"log"
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

		c.SetCookie("SESSIONID", sessionId, 3600, "/", "localhost", false, true)
	})

	// Use Casbin authentication middleware.
	auth, err := gcasbin.NewCasbinMiddleware("examples/config/model.conf", "examples/config/policy.csv", subjectFromSession)
	if err != nil {
		log.Fatal(err)
	}

	r.GET("/book", auth.RequiresPermissions([]string{"book:read"}, gcasbin.AND), func(c *gin.Context) {
		c.String(200, "you read the book successfully")
	})
	r.POST("/book", auth.RequiresRoles([]string{"user"}, gcasbin.AND), func(c *gin.Context) {
		c.String(200, "you posted a book successfully")
	})

	r.Run()
}

// subjectFromSession get subject from session.
func subjectFromSession(c *gin.Context, _ ...interface{}) string {
	// Get session ID from cookie.
	sessionId, err := c.Cookie("SESSIONID")
	if err != nil {
		// Cookie not found.
		return ""
	}

	// Get subject from session.
	session := sessions.Default(c)
	if subject, ok := session.Get(sessionId).(string); !ok {
		return ""
	} else {
		return subject
	}
}
