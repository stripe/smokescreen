package smokescreen

import "errors"

type missingRoleError struct {
	error
}

type denyError struct {
	error
}

func MissingRoleError(s string) error {
	return missingRoleError{errors.New(s)}
}

func IsMissingRoleError(err error) bool {
	_, ok := err.(missingRoleError)
	return ok
}
