package cryptutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

type AES128Key [16]byte
type AES192Key [24]byte
type AES256Key [32]byte

type AES struct {
	key []byte
	iv  []byte
	b   cipher.Block
}

func (k AES256Key) String() string {
	buf := bytes.NewBufferString("")
	for i, b := range k {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(fmt.Sprintf("0x%x", b))
	}
	return buf.String()
}

func (k AES128Key) String() string {
	buf := bytes.NewBufferString("")
	for i, b := range k {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(fmt.Sprintf("0x%x", b))
	}
	return buf.String()
}

func (k AES192Key) String() string {
	buf := bytes.NewBufferString("")
	for i, b := range k {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(fmt.Sprintf("0x%x", b))
	}
	return buf.String()
}

func newAES(key []byte) *AES {
	b, _ := aes.NewCipher(key)
	return &AES{
		key: key[:],
		iv:  key[:aes.BlockSize],
		b:   b,
	}
}

// NewAES128 cipher with AES-128
func NewAES128(key AES128Key) *AES {
	return newAES(key[:])
}

// NewAES192 cipher with AES-192
func NewAES192(key AES192Key) *AES {
	return newAES(key[:])
}

// NewAES256 cipher with AES-256
func NewAES256(key AES256Key) *AES {
	return newAES(key[:])
}

// CFBEncrypt encrypt with CFB cipher
func (a *AES) CFBEncrypt(buf []byte) []byte {
	dst := make([]byte, len(buf))
	cipher.NewCFBEncrypter(a.b, a.iv).XORKeyStream(dst, buf)
	return dst
}

// CFBDecrypt decrypt with CFB cipher
func (a *AES) CFBDecrypt(buf []byte) []byte {
	dst := make([]byte, len(buf))
	cipher.NewCFBDecrypter(a.b, a.iv).XORKeyStream(dst, buf)
	return dst
}

// CBCEncrypt encrypt with CBC cipher. padding with PKCS7
func (a *AES) CBCEncrypt(buf []byte) []byte {
	buf = PKCS7Padding(buf, a.b.BlockSize())
	dst := make([]byte, len(buf))
	cipher.NewCBCEncrypter(a.b, a.iv).CryptBlocks(dst, buf)
	return dst
}

// CBCDecrypt decrypt with CBC cipher. trimming with PKCS7
func (a *AES) CBCDecrypt(buf []byte) ([]byte, error) {
	if len(buf)%a.b.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid input length: %d", len(buf))
	}
	dst := make([]byte, len(buf))
	cipher.NewCBCDecrypter(a.b, a.iv).CryptBlocks(dst, buf)
	return PKCS7Trimming(dst)
}
