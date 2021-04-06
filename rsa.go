package cryptutil

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

const (
	// RSA default E
	RSADefaultExponent = 65537
)
// RSAPublicKeyFromBytes create *rsa.PublicKey from n bytes. if e zero use 65537
func RSAPublicKeyFromBytes(n []byte, e int) *rsa.PublicKey {
	if e == 0 {
		e = RSADefaultExponent
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: e,
	}
}

// RSAPublicKeyFromString create *rsa.PublicKey from n string. if e zero use 65537
// The base argument must be 0 or a value between 2 and MaxBase. For base 0, the number prefix determines the actual base: A prefix of “0b” or “0B” selects base 2, “0”, “0o” or “0O” selects base 8, and “0x” or “0X” selects base 16. Otherwise, the selected base is 10 and no prefix is accepted.
// For bases <= 36, lower and upper case letters are considered the same: The letters 'a' to 'z' and 'A' to 'Z' represent digit values 10 to 35. For bases > 36, the upper case letters 'A' to 'Z' represent the digit values 36 to 61.
// For base 0, an underscore character “_” may appear between a base prefix and an adjacent digit, and between successive digits; such underscores do not change the value of the number. Incorrect placement of underscores is reported as an error if there are no other errors. If base != 0, underscores are not recognized and act like any other character that is not a valid digit.
func RSAPublicKeyFromString(n string, e int, base int) (*rsa.PublicKey, error) {
	i, ok := new(big.Int).SetString(n, base)
	if !ok {
		return nil, fmt.Errorf("invalid n/base value")
	}

	if e == 0 {
		e = RSADefaultExponent
	}

	return &rsa.PublicKey{
		N: i,
		E: e,
	}, nil
}

// RSAEncryptPKCS1v15 encrypt buf with PKCS1v15
func RSAEncryptPKCS1v15(buf []byte, key *rsa.PublicKey) ([]byte, error) {
	var data []byte
	k := ((key.N.BitLen() + 7) / 8) - 11
	for {
		arr, err := rsa.EncryptPKCS1v15(rand.Reader, key, buf[:k])
		if err != nil {
			return nil, err
		}
		data = append(data, arr...)
		if len(buf) <= k {
			break
		}
		buf = buf[k:]
	}
	return data, nil
}

// RSAEncrypt encrypt buf with PKCS1v15
func RSAEncrypt(buf []byte, key []byte) ([]byte, error) {
	pub := RSAPublicKeyFromBytes(key, RSADefaultExponent)
	return RSAEncryptPKCS1v15(buf, pub)
}

// RSAEncryptNoPadding calc rsa encrypt with no padding
func RSAEncryptNoPadding(buf []byte, key *rsa.PublicKey) []byte {
	c := new(big.Int)
	c.Exp(new(big.Int).SetBytes(buf), big.NewInt(int64(key.E)), key.N)
	return c.Bytes()
}
