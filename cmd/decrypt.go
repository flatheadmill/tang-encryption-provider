package main

import (
	"fmt"
	"os"

	"io/ioutil"

	"github.com/lainio/err2"
	"github.com/bigeasy/tang-encryption-provider/crypter"
)

func main() {
	input, err := ioutil.ReadAll(os.Stdin)
	err2.Check(err)

	plaintext, err := crypter.Decrypt(string(input))

	fmt.Printf("%v\n", string(plaintext))
}
