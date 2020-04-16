package main

import (
	"github.com/gbrlsnchs/jwt/v3"
	"github.com/gin-gonic/gin"
	gcasbin "github.com/maxwellhertz/gin-casbin"
	"strings"
	"time"
)

var jwtKey = jwt.NewHS256([]byte("your key"))

func main() {
	r := gin.Default()

	r.POST("/login", func(c *gin.Context) {
		// Verify username and password.
		// ...

		// If this user logged in successfully, give him/her a new JWT.
		// Remember to assign value to subject header.
		payload := jwt.Payload{
			Subject:        "alice",
			ExpirationTime: jwt.NumericDate(time.Now().Add(time.Hour)),
		}
		token, err := jwt.Sign(payload, jwtKey)
		if err != nil {
			c.JSON(500, "some error")
			return
		}
		c.JSON(200, string(token))
	})

	// Use Casbin authentication middleware.
	auth := gcasbin.NewAuthMiddleware("examples/config/model.conf", "examples/config/policy.csv", subjectFromJWT)
	r.GET("/book", auth.Enforce("book", "read"), func(c *gin.Context) {
		c.String(200, "you read the book successfully")
	})

	r.Run()
}

// subjectFromJWT parses a JWT and extract subject from sub claim.
func subjectFromJWT(c *gin.Context, _ ...interface{}) interface{} {
	authHeader := c.Request.Header.Get("Authorization")
	prefix := "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		// Incorrect Authorization header format.
		return ""
	}
	token := authHeader[strings.Index(authHeader, prefix)+len(prefix):]
	if token == "" {
		// JWT not found.
		return nil
	}

	var payload jwt.Payload
	_, err := jwt.Verify([]byte(token), jwtKey, &payload)
	if err != nil {
		return nil
	}
	return payload.Subject
}