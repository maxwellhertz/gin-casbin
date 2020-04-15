package casbin

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func ExampleAuthMiddleware() {
	r := gin.Default()

	r.POST("/login", func(c *gin.Context) {
		// Verify username and password.
		// ...

		// If this user logged in successfully, give him/her a new JWT.
		// Remember to assign value to subject header.
		claims := &jwt.StandardClaims{
			Subject:   "alice",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, err := token.SignedString([]byte("your key"))
		if err != nil {
			c.String(500, "some error")
			return
		}
		c.String(200, ss)
	})

	// Use Casbin authentication middleware.
	auth := NewAuthMiddleware(
		"path/to/model.conf",
		"path/to/policy.csv",
		func(token *jwt.Token) (interface{}, error) {
			return []byte("your key"), nil
		})
	r.GET("/book", auth.Enforce("book", "read"), func(c *gin.Context) {
		c.String(200, "you read the book successfully")
	})

	r.Run()
}
