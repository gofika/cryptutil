package cryptutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRSA(t *testing.T) {
	privyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if !assert.Nil(t, err) {
		return
	}
	pubKey := &privyKey.PublicKey
	buf := x509.MarshalPKCS1PublicKey(pubKey)

	key := RSAPublicKeyFromBytes(pubKey.N.Bytes(), 0)
	assert.True(t, pubKey.Equal(key))

	key, err = x509.ParsePKCS1PublicKey(buf)
	if !assert.Nil(t, err) {
		return
	}
	assert.True(t, pubKey.Equal(key))
}
