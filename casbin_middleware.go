package gcasbin

import (
	"errors"
	"log"
	"sort"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

type CasbinMiddleware struct {
	enforcer *casbin.Enforcer
	subFn    SubjectFn
}

// SubjectFn is used to look up current subject in runtime.
// If it can not find anything, just return an empty string.
type SubjectFn func(c *gin.Context) string

// Logic is the logical operation (AND/OR) used in permission checks
// in case multiple permissions or roles are specified.
type Logic int

const (
	AND Logic = iota
	OR
)

var (
	ErrSubFnNil = errors.New("subFn is nil")
)

// NewCasbinMiddleware returns a new CasbinMiddleware using Casbin's Enforcer internally.
// modelFile is the file path to Casbin model file e.g. path/to/rbac_model.conf.
// policyAdapter can be a file or a DB adapter.
// File: path/to/basic_policy.csv
// MySQL DB: mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// subFn is a function that looks up the current subject in runtime and returns an empty string if nothing found.
func NewCasbinMiddleware(modelFile string, policyAdapter interface{}, subFn SubjectFn) (*CasbinMiddleware, error) {
	if subFn == nil {
		return nil, ErrSubFnNil
	}

	e, err := casbin.NewEnforcer(modelFile, policyAdapter)
	if err != nil {
		return nil, err
	}

	return &CasbinMiddleware{
		enforcer: e,
		subFn:    subFn,
	}, nil
}

// Option is used to change some default behaviors.
type Option interface {
	apply(*options)
}

type options struct {
	logic Logic
}

type logicOption Logic

func (lo logicOption) apply(opts *options) {
	opts.logic = Logic(lo)
}

// WithLogic sets the logical operator used in permission or role checks.
func WithLogic(logic Logic) Option {
	return logicOption(logic)
}

// RequiresPermissions tries to find the current subject by calling SubjectFn
// and determine if the subject has the required permissions according to predefined Casbin policies.
// permissions are formatted strings. For example, "file:read" represents the permission to read a file.
// opts is some optional configurations such as the logical operator (default is AND) in case multiple permissions are specified.
func (am *CasbinMiddleware) RequiresPermissions(permissions []string, opts ...Option) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(permissions) == 0 {
			c.Next()
			return
		}

		// Here we provide default options.
		actualOptions := options{
			logic: AND,
		}
		// Apply actual options.
		for _, opt := range opts {
			opt.apply(&actualOptions)
		}

		// Look up current subject.
		sub := am.subFn(c)
		if sub == "" {
			c.AbortWithStatus(401)
			return
		}

		// Enforce Casbin policies.
		if actualOptions.logic == AND {
			// Must pass all tests.
			for _, permission := range permissions {
				obj, act := parsePermissionStrings(permission)
				if obj == "" || act == "" {
					// Can not handle any illegal permission strings.
					log.Println("illegal permission string: ", permission)
					c.AbortWithStatus(500)
					return
				}

				if ok, err := am.enforcer.Enforce(sub, obj, act); !ok || err != nil {
					c.AbortWithStatus(401)
					return
				}
			}
			c.Next()
		} else {
			// Need to pass at least one test.
			for _, permission := range permissions {
				obj, act := parsePermissionStrings(permission)
				if obj == "" || act == "" {
					log.Println("illegal permission string: ", permission)
					c.AbortWithStatus(500)
					continue
				}

				if ok, err := am.enforcer.Enforce(sub, obj, act); ok && err == nil {
					c.Next()
					return
				}
			}
			c.AbortWithStatus(401)
		}
	}
}

func parsePermissionStrings(str string) (string, string) {
	if !strings.Contains(str, ":") {
		return "", ""
	}
	vals := strings.Split(str, ":")
	return vals[0], vals[1]
}

// RequiresPermissions tries to find the current subject by calling SubjectFn
// and determine if the subject has the required roles according to predefined Casbin policies.
// opts is some optional configurations such as the logical operator (default is AND) in case multiple roles are specified.
func (am *CasbinMiddleware) RequiresRoles(requiredRoles []string, opts ...Option) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(requiredRoles) == 0 {
			c.Next()
			return
		}

		// Look up current subject.
		sub := am.subFn(c)
		if sub == "" {
			c.AbortWithStatus(401)
			return
		}

		// Here we provide default options.
		actualOptions := options{
			logic: AND,
		}
		// Apply actual options.
		for _, opt := range opts {
			opt.apply(&actualOptions)
		}

		actualRoles, err := am.enforcer.GetRolesForUser(sub)
		if err != nil {
			log.Println("couldn't get roles of subject: ", err)
			c.AbortWithStatus(500)
			return
		}

		// Enforce Casbin policies.
		sort.Strings(requiredRoles)
		sort.Strings(actualRoles)
		if actualOptions.logic == AND {
			// Must have all required roles.
			for _, role := range requiredRoles {
				ii := sort.SearchStrings(actualRoles, role)
				if ii >= len(actualRoles) || actualRoles[ii] != role {
					c.AbortWithStatus(401)
				}
			}
			c.Next()
		} else {
			// Need to have at least one of required roles.
			for _, requiredRole := range requiredRoles {
				if i := sort.SearchStrings(actualRoles, requiredRole); i >= 0 &&
					i < len(actualRoles) &&
					actualRoles[i] == requiredRole {
					c.Next()
					return
				}
			}
			c.AbortWithStatus(401)
		}
	}
}
