package casbin

import (
	lcasbin "github.com/casbin/casbin"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"log"
	"strings"
)

type AuthMiddleware struct {
	enforcer *lcasbin.Enforcer
	jwtKeyFn jwt.Keyfunc
}

// NewAuthMiddleware returns a new AuthMiddleware using Casbin's Enforcer internally.
// modelFile is the file path to Casbin model file e.g. path/to/rbac_model.conf.
// policyAdapter can be a file or a DB adapter.
// File: path/to/basic_policy.csv
// MySQL DB: mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// jwtKeyFn allows you to use properties in the Header of the token (such as `kid`) to identify which key to use,
// see https://pkg.go.dev/github.com/dgrijalva/jwt-go?tab=doc#Keyfunc.
func NewAuthMiddleware(modelFile string, policyAdapter interface{}, jwtKeyFn jwt.Keyfunc) *AuthMiddleware {
	enforcer := lcasbin.NewEnforcer(modelFile, policyAdapter)
	return &AuthMiddleware{enforcer: enforcer, jwtKeyFn: jwtKeyFn}
}

// Enforce tries to find the current subject from JWT's sub header
// and enforces predefined Casbin policies.
func (am *AuthMiddleware) Enforce(obj string, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Look up current subject from JWT.
		authHeader := c.Request.Header.Get("Authorization")
		prefix := "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			// Incorrect Authorization header format.
			c.AbortWithStatus(400)
			return
		}
		token := authHeader[strings.Index(authHeader, prefix)+len(prefix):]
		if token == "" {
			// JWT not found.
			c.AbortWithStatus(400)
			return
		}
		parsedToken, err := jwt.Parse(token, am.jwtKeyFn)
		if err != nil {
			if _, ok := err.(*jwt.ValidationError); ok {
				// Invalid token.
				c.AbortWithStatus(401)
			} else {
				// Could't handle this token.
				log.Println("couldn't handle JWT: ", err)
				c.AbortWithStatus(500)
			}
			return
		}
		if !parsedToken.Valid {
			// Invalid token.
			c.AbortWithStatus(401)
			return
		}

		// Get the subject.
		claims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			// Could't handle this token.
			log.Println("couldn't handle JWT: ", err)
			c.AbortWithStatus(500)
		}
		sub := claims["sub"]

		// Enforce Casbin policy.
		if ok := am.enforcer.Enforce(sub, obj, act); !ok {
			c.AbortWithStatus(403)
			return
		}

		c.Next()
	}
}
