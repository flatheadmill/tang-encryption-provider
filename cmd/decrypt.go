package main

import (
	"fmt"
	"os"

	"io/ioutil"

	"github.com/lainio/err2/try"

	crypter "github.com/flatheadmill/tang-encryption-provider/lestrrat"
)

func main() {
	input := try.To1(ioutil.ReadAll(os.Stdin))
	plain := try.To1(crypter.Decrypt(input))
	fmt.Print(string(plain))
}
