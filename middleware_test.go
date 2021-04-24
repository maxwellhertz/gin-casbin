package gcasbin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	modelFile       = "./examples/config/model.conf"
	simplePolicy    = "./examples/config/policy.csv"
	readWritePolicy = "./examples/config/policy_read_write.csv"
	userAdminPolicy = "./examples/config/policy_user_admin.csv"
)

var (
	SubjectAlice = func(c *gin.Context) string { return "alice" }
	SubjectNil   = func(c *gin.Context) string { return "" }
)

func TestNewAuthMiddleware(t *testing.T) {
	table := []struct {
		subjectFn   SubjectFn
		expectedErr error
	}{
		{
			subjectFn:   nil,
			expectedErr: ErrSubFnNil,
		},
		{
			subjectFn:   SubjectAlice,
			expectedErr: nil,
		},
	}

	for _, entry := range table {
		_, err := NewCasbinMiddleware(modelFile, simplePolicy, entry.subjectFn)
		assert.Equal(t, entry.expectedErr, err)
	}
}

func TestRequiresPermissions(t *testing.T) {
	tests := []struct {
		policyFile   string
		subjectFn    SubjectFn
		permissions  []string
		logic        Logic
		expectedCode int
	}{
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:read"},
			logic:        AND,
			expectedCode: 200,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:read"},
			logic:        OR,
			expectedCode: 200,
		},
		{
			policyFile:   readWritePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:read", "book:write"},
			logic:        AND,
			expectedCode: 200,
		},
		{
			policyFile:   readWritePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:read", "book:write"},
			logic:        OR,
			expectedCode: 200,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectNil,
			permissions:  []string{"book:read"},
			logic:        AND,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:write"},
			logic:        AND,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:write"},
			logic:        OR,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:read", "book:write"},
			logic:        AND,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"book:review", "book:write"},
			logic:        OR,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"readbook"},
			logic:        AND,
			expectedCode: 500,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{":"},
			logic:        AND,
			expectedCode: 500,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{"readbook"},
			logic:        OR,
			expectedCode: 500,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			permissions:  []string{":"},
			logic:        OR,
			expectedCode: 500,
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.subjectFn)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresPermissions(tt.permissions, WithLogic(tt.logic)))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/book", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, tt.expectedCode, w.Code)
	}
}

func TestRequiresRoles(t *testing.T) {
	tests := []struct {
		policyFile   string
		subjectFn    SubjectFn
		roles        []string
		logic        Logic
		expectedCode int
	}{
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"user"},
			logic:        AND,
			expectedCode: 200,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"user"},
			logic:        OR,
			expectedCode: 200,
		},
		{
			policyFile:   userAdminPolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"user", "admin"},
			logic:        AND,
			expectedCode: 200,
		},
		{
			policyFile:   userAdminPolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"user", "admin"},
			logic:        OR,
			expectedCode: 200,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectNil,
			roles:        []string{"user"},
			logic:        AND,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"admin"},
			logic:        AND,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"admin"},
			logic:        OR,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"user", "admin"},
			logic:        AND,
			expectedCode: 401,
		},
		{
			policyFile:   simplePolicy,
			subjectFn:    SubjectAlice,
			roles:        []string{"root", "admin"},
			logic:        OR,
			expectedCode: 401,
		},
	}

	for _, tt := range tests {
		middleware, err := NewCasbinMiddleware(modelFile, tt.policyFile, tt.subjectFn)
		if err != nil {
			t.Fatal(err)
		}

		r := setupRouter(middleware.RequiresRoles(tt.roles, WithLogic(tt.logic)))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/book", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, tt.expectedCode, w.Code)
	}
}

func setupRouter(casbinMiddleware gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.GET("/book", casbinMiddleware, func(c *gin.Context) {
		c.String(200, "success")
	})

	return r
}
