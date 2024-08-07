package acme

import (
	"bytes"
	"fmt"
	"runtime"
)

func recoverValueString(value interface{}) (msg string) {
	switch v := value.(type) {
	case error:
		msg = v.Error()
	case string:
		msg = v
	default:
		msg = fmt.Sprintf("%#v", v)
	}

	return
}

func stackTrace(skip, depth int) string {
	pc := make([]uintptr, depth)

	// Always skip runtime.Callers and Stacktrace
	nbFrames := runtime.Callers(skip+2, pc)
	pc = pc[:nbFrames]

	var buf bytes.Buffer

	frames := runtime.CallersFrames(pc)
	for {
		frame, more := frames.Next()

		filePath := frame.File
		line := frame.Line
		function := frame.Function

		fmt.Fprintf(&buf, "%s\n", function)
		fmt.Fprintf(&buf, "  %s:%d\n", filePath, line)

		if !more {
			break
		}
	}

	return buf.String()
}
