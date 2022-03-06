package main

import (
	"crypto"
	"fmt"
	"strings"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/goware/urlx"
	"github.com/lainio/err2"
)

func base64Decode(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

type jsonTang struct {
	Location      string             `json:"url"`
	Advertisement jose.JSONWebKeySet `json:"adv"`
}

type jsonClevis struct {
	Plugin string   `json:"pin"`
	Tang   jsonTang `json:"tang"`
}

const Thumbprint = "o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY"

type Crypter struct {
	recipient        jose.Recipient
	encrypterOptions jose.EncrypterOptions
}

func NewCrypter(url string, fingerprint string) (Crypter, error) {
	url = strings.TrimSuffix(url, "/")
	parsed, err := urlx.Parse(url)
	err2.Check(err)
	url, err = urlx.Normalize(parsed)
	err2.Check(err)
	_, err = base64Decode(fingerprint)
	err2.Check(err)
	advGet, err := http.Get(fmt.Sprintf("%s/adv/%s", url, fingerprint))
	err2.Check(err)
	defer advGet.Body.Close()

	advJSON, err := ioutil.ReadAll(advGet.Body)
	err2.Check(err)

	var adv map[string]interface{}
	err = json.Unmarshal(advJSON, &adv)
	err2.Check(err)

	payload, err := base64.RawURLEncoding.DecodeString(adv["payload"].(string))
	err2.Check(err)

	// TODO Missing verification. Just want to get it into an object for now.

	var keySet jose.JSONWebKeySet
	err = json.Unmarshal(payload, &keySet)
	err2.Check(err)

	var deriver *jose.JSONWebKey
Keys:
	for _, key := range keySet.Keys {
		for _, op := range key.KeyOps {
			if op == "deriveKey" {
				deriver = &key
				break Keys
			}
		}
	}
	deriver.Algorithm = ""
	deriver.KeyOps = nil

	extraHeaders := make(map[jose.HeaderKey]interface{})

	extraHeaders["clevis"] = jsonClevis{
		Plugin: "tang",
		Tang: jsonTang{
			Location:      "http://tang:8080",
			Advertisement: keySet,
		},
	}

	thumbprint, err := deriver.Thumbprint(crypto.SHA256)
	err2.Check(err)
	extraHeaders["kid"] = base64.RawURLEncoding.EncodeToString(thumbprint)

	return Crypter{
		encrypterOptions: jose.EncrypterOptions{ExtraHeaders: extraHeaders},
		recipient:        jose.Recipient{Algorithm: jose.ECDH_ES, Key: deriver.Key},
	}, nil
}

func (c *Crypter) Encrypt([]byte) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, c.recipient, &c.encrypterOptions)
	err2.Check(err)
	cipher, err := encrypter.Encrypt([]byte("hi\n"))
	err2.Check(err)
	compact, err := cipher.CompactSerialize()
	err2.Check(err)
	return compact, nil
}

func main() {
	crypter, err := NewCrypter("http://tang:8080", Thumbprint)
	err2.Check(err)
	compact, err := crypter.Encrypt([]byte("hi\n"))
	err2.Check(err)
	fmt.Println(compact)
}
