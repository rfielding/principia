package common

import (
	"encoding/json"
	"fmt"
)

type Logger func(mask string, argv ...interface{}) (int, error)

func AsJsonPretty(obj interface{}) []byte {
	s, _ := json.MarshalIndent(obj, "", "  ")
	return s
}

func NewLogger(id string) Logger {
	return func(mask string, argv ...interface{}) (int, error) {
		mask = "%s: " + mask + "\n"
		argv2 := make([]interface{}, 0)
		argv2 = append(argv2, id)
		argv2 = append(argv2, argv...)
		return fmt.Printf(mask, argv2...)
	}
}
