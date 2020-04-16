package gcasbin

import (
	"errors"
	lcasbin "github.com/casbin/casbin"
	"github.com/gin-gonic/gin"
	"log"
	"reflect"
	"sort"
	"strings"
)

type CasbinMiddleware struct {
	enforcer *lcasbin.Enforcer
	subFn    SubjectFn
}

// SubjectFn is used to look up current subject in runtime.
// If it can not find anything, just return an empty string.
type SubjectFn func(c *gin.Context, args ...interface{}) string

// Logic is the logical operation (AND/OR) used in permission checks
// in case multiple permissions or roles are specified.
type Logic int

const (
	AND Logic = iota
	OR
)

var (
	SubFnNilErr = errors.New("subFn is nil")
)

// NewCasbinMiddleware returns a new CasbinMiddleware using Casbin's Enforcer internally.
// modelFile is the file path to Casbin model file e.g. path/to/rbac_model.conf.
// policyAdapter can be a file or a DB adapter.
// File: path/to/basic_policy.csv
// MySQL DB: mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
// subFn is a function that looks up the current subject in runtime and returns an empty string if nothing found.
func NewCasbinMiddleware(modelFile string, policyAdapter interface{}, subFn SubjectFn) (*CasbinMiddleware, error) {
	if subFn == nil {
		return nil, SubFnNilErr
	}

	return &CasbinMiddleware{
		enforcer: lcasbin.NewEnforcer(modelFile, policyAdapter),
		subFn:    subFn,
	}, nil
}

// RequiresPermissions tries to find the current subject by calling SubjectFn
// and determine if the subject has the required permissions according to predefined Casbin policies.
// permissions are formatted strings. For example, "file:read" represents the permission to read a file.
// logic is the logical operation for the permissions checks in case multiple permissions are specified.
// subFnArgs is used in SubjectFn.
func (am *CasbinMiddleware) RequiresPermissions(permissions []string, logic Logic, subFnArgs ...interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Look up current subject.
		sub := am.subFn(c, subFnArgs)
		if sub == "" {
			c.AbortWithStatus(401)
			return
		}

		if len(permissions) == 0 {
			c.Next()
			return
		}

		// Enforce Casbin policies.
		if logic == AND {
			// Must pass all tests.
			for _, permission := range permissions {
				obj, act := parsePermissionStrings(permission)
				if obj == "" || act == "" {
					// Can not handle any illegal permission strings.
					log.Println("illegal permission string: ", permission)
					c.AbortWithStatus(500)
					return
				}

				if ok := am.enforcer.Enforce(sub, obj, act); !ok {
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

				if ok := am.enforcer.Enforce(sub, obj, act); ok {
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
// logic is the logical operation for the permissions checks in case multiple roles are specified.
// subFnArgs is used in SubjectFn.
func (am *CasbinMiddleware) RequiresRoles(requiredRoles []string, logic Logic, subFnArgs ...interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Look up current subject.
		sub := am.subFn(c, subFnArgs)
		if sub == "" {
			c.AbortWithStatus(401)
			return
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
		if logic == AND {
			// Must have all required roles.
			if !reflect.DeepEqual(requiredRoles, actualRoles) {
				c.AbortWithStatus(401)
			} else {
				c.Next()
			}
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
