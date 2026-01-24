package plugin

import (
	"errors"
)

var (
	ErrForbidden    = errors.New("authorization has been refused")
	ErrUnauthorized = errors.New("authentication has been refused")
	ErrUnacceptable = errors.New("plugin is not applicable to the provided input")
)

// IsError is a helper method to compare errors that have
// been serialized and transmitted via RPC. the recommended
// way to compare errors using [errors#Is] does not work as
// the deserialized error and the comparison input are two
// distinct error instances (presumably created via [errors.New])
// that happen to have the same error message but have different
// pointer addresses. IsError compares the message of the
// provided errors without unwrapping either of them.
func IsError(err, target error) bool {
	if err == nil || target == nil {
		return err == target
	}

	return err.Error() == target.Error()
}
