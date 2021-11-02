[![codecov](https://codecov.io/gh/gofika/cryptutil/branch/main/graph/badge.svg)](https://codecov.io/gh/gofika/cryptutil)
[![Build Status](https://github.com/gofika/cryptutil/workflows/build/badge.svg)](https://github.com/gofika/cryptutil)
[![go.dev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/gofika/cryptutil)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofika/cryptutil)](https://goreportcard.com/report/github.com/gofika/cryptutil)
[![Licenses](https://img.shields.io/github/license/gofira/cryptutil)](LICENSE)

# CryptUtil

crypt algorithm wrapper for easy use RSA,AES,DES and others.

## Basic Usage

### Installation

To get the package, execute:

```bash
go get github.com/gofika/cryptutil
```

### DES

```go
package main

import (
  "fmt"
  "github.com/gofika/cryptutil"
)

func main() {
  // your des key
  key := cryptutil.DESKey{1, 2, 3, 4, 5, 6, 7, 8}

  des := cryptutil.NewDES(key)
  content := "Foo"
  // CFB encrypt
  encrypted := des.CFBEncrypt([]byte(content))
  fmt.Println(encrypted)
  // CFG decrypt
  decrypted := des.CFBDecrypt(encrypted)
  fmt.Println(decrypted)
}
```