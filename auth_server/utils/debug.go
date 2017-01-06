package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

// PrintPretty prints struct v as format json
func PrintPretty(v interface{}, mark string) (err error) {
	fmt.Printf("*********%s\n", mark)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	data = append(data, '\n')
	os.Stdout.Write(data)
	return
}
