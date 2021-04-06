package cryptutil

import (
	. "gopkg.in/check.v1"
	"testing"
)

func Test(t *testing.T) { TestingT(t) }

type CryptUtilSuite struct{}

var _ = Suite(&CryptUtilSuite{})
