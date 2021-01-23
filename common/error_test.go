package common

import (
	"errors"
	"testing"
)

func TestCombineError(t *testing.T) {
	var set = []struct{
		err []error
		str string
	}{
		{
			err: []error{errors.New("1")},
			str: "1",
		},
		{
			err: []error{errors.New("1"), errors.New("2")},
			str: "1, err: 2",
		},
		{
			err: []error{errors.New("1"), errors.New("2"), errors.New("3")},
			str: "1, err: 2, err: 3",
		},
		{
			err: []error{errors.New("1"), errors.New("2"), errors.New("3"), errors.New("4")},
			str: "1, err: 2, err: 3, err: 4",
		},
	}

	for i := range set {
		if CombineError(set[i].err...).Error() != set[i].str {
			t.Errorf("got error: %s\n", set[i].str)
		}
	}
}
