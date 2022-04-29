package handler

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

func Handler(err *error) func() {
	// https://stackoverflow.com/questions/47218715/is-it-possible-to-get-filename-where-code-is-called-in-golang
	// https://github.com/cockroachdb/cockroach/issues/17770
	_, file, _, _ := runtime.Caller(1)
	return func() {
		stack := string(debug.Stack())
		split := strings.Split(stack, "\n")
		for i, line := range split {
			if strings.Contains(line, file) {
				stack = strings.Join(split[i-1:len(split)-1], "\n")
				break
			}
		}
		*err = fmt.Errorf("%w:\n%s", *err, stack)
	}
}
