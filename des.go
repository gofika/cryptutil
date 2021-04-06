package cryptutil

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

type DESKey [8]byte

func (k DESKey) String() string {
	buf := bytes.NewBufferString("")
	for i, b := range k {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(fmt.Sprintf("0x%x", b))
	}
	return buf.String()
}

type DES struct {
	key DESKey
	b   cipher.Block
	iv  []byte
}

func NewDES(key DESKey) *DES {
	b, _ := des.NewCipher(key[:])
	return &DES{
		key: key,
		b:   b,
		iv:  key[:des.BlockSize],
	}
}

// CFBEncrypt encrypt with CFB cipher
func (d *DES) CFBEncrypt(buf []byte) []byte {
	dst := make([]byte, len(buf))
	cipher.NewCFBEncrypter(d.b, d.iv).XORKeyStream(dst, buf)
	return dst
}

// CFBDecrypt decrypt with CFB cipher
func (d *DES) CFBDecrypt(buf []byte) []byte {
	dst := make([]byte, len(buf))
	cipher.NewCFBDecrypter(d.b, d.iv).XORKeyStream(dst, buf)
	return dst
}

// CBCEncrypt encrypt with CBC cipher. padding with PKCS7
func (d *DES) CBCEncrypt(buf []byte) []byte {
	buf = PKCS7Padding(buf, d.b.BlockSize())
	dst := make([]byte, len(buf))
	cipher.NewCBCEncrypter(d.b, d.iv).CryptBlocks(dst, buf)
	return dst
}

// CBCDecrypt decrypt with CBC cipher. trimming with PKCS7
func (d *DES) CBCDecrypt(buf []byte) ([]byte, error) {
	if len(buf)%d.b.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid input length: %d", len(buf))
	}
	dst := make([]byte, len(buf))
	cipher.NewCBCDecrypter(d.b, d.iv).CryptBlocks(dst, buf)
	return PKCS7Trimming(dst)
}
