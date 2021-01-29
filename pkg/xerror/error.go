package xerror

import "fmt"

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
