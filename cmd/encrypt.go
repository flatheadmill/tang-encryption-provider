package main

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/bigeasy/tang-encryption-provider/crypter"
)

const Thumbprint = "o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY"

func main() {
	encrypter, err := crypter.NewCrypter("http://tang:8080", Thumbprint)
	err2.Check(err)
	compact, err := encrypter.Encrypt([]byte("hi\n"))
	err2.Check(err)
	fmt.Println(compact)
}
