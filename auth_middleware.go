package gcasbin

import (
	lcasbin "github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	enforcer *lcasbin.Enforcer
	subFn SubjectFn
}

// SubjectFn is used to look up current subject in runtime.
// If it can not find anything, just return an empty string.
type SubjectFn func(c *gin.Context, args ...interface{}) interface{}

// NewAuthMiddleware returns a new AuthMiddleware using Casbin's Enforcer internally.
// modelFile is the file path to Casbin model file e.g. path/to/rbac_model.conf.
// policyAdapter can be a file or a DB adapter.
// File: path/to/basic_policy.csv
// MySQL DB: mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// subFn is a function that looks up the current subject in runtime and returns an empty string if nothing found.
func NewAuthMiddleware(modelFile string, policyAdapter interface{}, subFn SubjectFn) *AuthMiddleware {
	enforcer := lcasbin.NewEnforcer(modelFile, policyAdapter)
	return &AuthMiddleware{enforcer: enforcer, subFn: subFn}
}

// Enforce tries to find the current subject from JWT's sub header
// and enforces predefined Casbin policies.
func (am *AuthMiddleware) Enforce(obj string, act string, args ...interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Look up current subject.
		sub := am.subFn(c, args)
		if sub == nil {
			c.AbortWithStatus(401)
			return
		}

		// Enforce Casbin policy.
		if ok := am.enforcer.Enforce(sub, obj, act); !ok {
			c.AbortWithStatus(401)
			return
		}

		c.Next()
	}
}
