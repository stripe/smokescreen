package smokescreen

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
)

func mockRFR(s string, e error) func(req *http.Request) (string, error) {
	return func(req *http.Request) (string, error) {
		return s, e
	}
}

func _testGetRole(t *testing.T, rfr_s string, rfr_e error, allow_missing bool, expect_s string, expect_e error) {
	config := Config{
		RoleFromRequest:  mockRFR(rfr_s, rfr_e),
		AllowMissingRole: allow_missing,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s, e := getRole(context.Background(), &config, config.Log, nil)
	if e != expect_e {
		t.Fatalf("expected err %v got %v\n", expect_e, e)
	}
	if s != expect_s {
		t.Fatalf("expected role %v got %v\n", expect_s, s)
	}
}

func TestGetRole(t *testing.T) {
	role := "some role"
	genErr := errors.New("general error")
	mre := MissingRoleError("missing role")

	t.Run("good", func(t *testing.T) {
		_testGetRole(t, role, nil, false, role, nil)
	})
	t.Run("bad", func(t *testing.T) {
		_testGetRole(t, "", genErr, false, "", genErr)
	})

	t.Run("missing not allowed -> err", func(t *testing.T) {
		_testGetRole(t, "", mre, false, "", mre)
	})
	t.Run("missing allowed -> empty role", func(t *testing.T) {
		_testGetRole(t, "", mre, true, "", nil)
	})
}
