package main

import (
	"fmt"
	"flag"
	"os"

	"io/ioutil"

	"github.com/lainio/err2"
	"github.com/bigeasy/tang-encryption-provider/crypter"
)

func main() {
	var (
		url         = flag.String("url", "", "url of tang server")
		thumbprint  = flag.String("thumbprint", "", "thumbprint of advertisement signing key")
	)
	flag.Parse();
	input, err := ioutil.ReadAll(os.Stdin)
	err2.Check(err)
	encrypter, err := crypter.NewCrypter(*url, *thumbprint)
	err2.Check(err)
	compact, err := encrypter.Encrypt(input)
	err2.Check(err)
	fmt.Println(compact)
}
