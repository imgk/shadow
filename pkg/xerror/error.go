package xerror

import (
	"errors"
	"fmt"
)

// Error is ...
type Error interface {
	error
	As(interface{}) bool
	Is(error) bool
}

type mError struct {
	Err []error
}

func (e *mError) Error() string {
	switch len(e.Err) {
	case 0:
		return "nil"
	case 1:
		return e.Err[0].Error()
	default:
		return fmt.Sprintf("%s, err: %v", e.Err[0], &mError{Err: e.Err[1:]})
	}
}

func (e *mError) Unwrap() error {
	switch len(e.Err) {
	case 0:
		return nil
	default:
		return e.Err[0]
	}
}

func (e *mError) As(v interface{}) bool {
	for _, err := range e.Err {
		if errors.As(err, v) {
			return true
		}
	}
	return false
}

func (e *mError) Is(v error) bool {
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
	return &mError{Err: me}
}
