package cryptutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	. "gopkg.in/check.v1"
)

func (s *CryptUtilSuite) TestRSA(c *C) {
	privyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)
	pubKey := &privyKey.PublicKey
	buf := x509.MarshalPKCS1PublicKey(pubKey)

	key := RSAPublicKeyFromBytes(pubKey.N.Bytes(), 0)
	c.Assert(pubKey.Equal(key), Equals, true)

	key, err = x509.ParsePKCS1PublicKey(buf)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Equal(key), Equals, true)
}
