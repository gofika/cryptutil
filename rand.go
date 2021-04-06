package cryptutil

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// GenerateAES128Key generate random AES128Key
func GenerateAES128Key() (ret AES128Key) {
	_, _ = rand.Read(ret[:])
	return ret
}

// GenerateAES192Key generate random AES192Key
func GenerateAES192Key() (ret AES192Key) {
	_, _ = rand.Read(ret[:])
	return ret
}

// GenerateAES256Key generate random AES256Key
func GenerateAES256Key() (ret AES256Key) {
	_, _ = rand.Read(ret[:])
	return ret
}

// GenerateDESKey generate random DESKey
func GenerateDESKey() (ret DESKey) {
	_, _ = rand.Read(ret[:])
	return ret
}
