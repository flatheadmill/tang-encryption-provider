package main

import (
	"fmt"
	"os"

	"io/ioutil"

	"github.com/bigeasy/tang-encryption-provider/crypter"
	"github.com/lainio/err2"
)

func main() {
	input, err := ioutil.ReadAll(os.Stdin)
	err2.Check(err)
	plaintext, err := crypter.Decrypt(input)
	err2.Check(err)
	fmt.Print(string(plaintext))
}
