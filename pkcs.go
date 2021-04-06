package cryptutil

import (
	"bytes"
	"fmt"
)

// PKCS7Padding padding bytes with PKCS7
func PKCS7Padding(buf []byte, blockSize int) []byte {
	padding := blockSize - len(buf)%blockSize
	buffer := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(buf, buffer...)
}

// PKCS7Trimming trimming bytes with PKCS7
func PKCS7Trimming(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("invalid input length: %d", len(buf))
	}

	padding := int(buf[len(buf)-1])
	if padding > len(buf) {
		return nil, fmt.Errorf("invalid padding length: %d", padding)
	}
	return buf[:len(buf)-padding], nil
}