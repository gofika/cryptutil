package cryptutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDES(t *testing.T) {
	key := DESKey{1, 2, 3, 4, 5, 6, 7, 8}
	des := NewDES(key)
	content := "Foo"
	encrypted := des.CFBEncrypt([]byte(content))
	assert.Len(t, encrypted, 3)
	decrypted := des.CFBDecrypt(encrypted)
	assert.Equal(t, content, string(decrypted))
}
