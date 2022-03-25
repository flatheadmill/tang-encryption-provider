package main

import (
	"flag"
	"fmt"
	"os"

	"io/ioutil"

	crypter "github.com/flatheadmill/tang-encryption-provider/lestrrat"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

func run(url string, thumbprint string) (err error) {
	err2.Return(&err)
	input := try.To1(ioutil.ReadAll(os.Stdin))
	encrypter := try.To1(crypter.NewCrypter(url, thumbprint))
	compact := try.To1(encrypter.Encrypt(input))
	fmt.Println(compact)
	return nil
}

func main() {
	var (
		url        = flag.String("url", "", "url of tang server")
		thumbprint = flag.String("thumbprint", "", "thumbprint of advertisement signing key")
	)
	flag.Parse()
	if err := run(*url, *thumbprint); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
