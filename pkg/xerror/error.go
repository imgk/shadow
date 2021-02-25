package xerror

import (
	"errors"
	"fmt"
)

// Error is ...
type Error struct {
	Err []error
}

// Error is ...
func (e *Error) Error() string {
	switch len(e.Err) {
	case 0:
		return "nil"
	case 1:
		return e.Err[0].Error()
	default:
		return fmt.Sprintf("%s, err: %v", e.Err[0], &Error{Err: e.Err[1:]})
	}
}

// Unwrap is ...
func (e *Error) Unwrap() error {
	switch len(e.Err) {
	case 0:
		return nil
	default:
		return e.Err[0]
	}
}

// As is ...
func (e *Error) As(v interface{}) bool {
	for _, err := range e.Err {
		if errors.As(err, v) {
			return true
		}
	}
	return false
}

// Is is ...
func (e *Error) Is(v error) bool {
	for _, err := range e.Err {
		if errors.Is(err, v) {
			return true
		}
	}
	return false
}

// CombineError is ...
func CombineError(err ...error) error {
	me := []error{}
	for _, e := range err {
		if e != nil {
			me = append(me, e)
		}
	}
	if len(me) == 0 {
		return nil
	}
	if len(me) == 1 {
		return me[0]
	}
	return &Error{Err: me}
}
