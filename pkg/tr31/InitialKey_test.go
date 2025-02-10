package tr31

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_generate_functions(t *testing.T) {
	data := "http://127.0.0.1:8200" + "hvs.XbDWbGIULgu9BXsrctyEuNg7"
	initialKey := GenerateIntialKey(data)
	assert.NotEqual(t, 0, len(initialKey))
}
func Test_empty_generate_functions(t *testing.T) {
	data := ""
	initialKey := GenerateIntialKey(data)
	assert.NotEqual(t, 0, len(initialKey))
}
