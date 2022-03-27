package crypter

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/goware/urlx"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"

	"github.com/anatol/clevis.go"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

func encode64(buffer []byte) string {
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func decode64(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

type jsonTang struct {
	Location      string          `json:"url"`
	Advertisement json.RawMessage `json:"adv"`
}

type jsonClevis struct {
	Plugin string   `json:"pin"`
	Tang   jsonTang `json:"tang"`
}

type Crypter struct {
	keyID       string
	headers     jwe.Headers
	exchangeKey jwk.Key
}

func findKey(keySet jwk.Set, sought jwk.KeyOperation) (key jwk.Key, err error) {
	defer err2.Return(&err)
	ctx := context.Background()
	for iterator := keySet.Iterate(ctx); iterator.Next(ctx); {
		key := iterator.Pair().Value.(jwk.Key)
		for _, op := range key.KeyOps() {
			if op == sought {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("key for operation %s not found", sought)
}

func NewCrypter(url string, thumbprint string) (crypter *Crypter, err error) {
	defer err2.Return(&err)

	try.To1(decode64(thumbprint))

	url = try.To1(urlx.Normalize(try.To1(urlx.Parse(strings.TrimSuffix(url, "/")))))
	advGet := try.To1(http.Get(fmt.Sprintf("%s/adv/%s", url, thumbprint)))
	defer advGet.Body.Close()

	advJSON := try.To1(ioutil.ReadAll(advGet.Body))

	message := try.To1(jws.Parse(advJSON))
	keySet := try.To1(jwk.Parse(message.Payload()))
	verifyKey := try.To1(findKey(keySet, jwk.KeyOpVerify))
	if thumbprint != encode64(try.To1(verifyKey.Thumbprint(crypto.SHA256))) {
		return nil, fmt.Errorf("unable to find key matching %v\n", thumbprint)
	}
	try.To1(jws.Verify(advJSON, "ES512", verifyKey))

	exchangeKey := try.To1(findKey(keySet, jwk.KeyOpDeriveKey))
	err2.Check(exchangeKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{}))
	err2.Check(exchangeKey.Set(jwk.AlgorithmKey, ""))

	headers := jwe.NewHeaders()

	err2.Check(headers.Set(jwe.KeyIDKey, encode64(try.To1(exchangeKey.Thumbprint(crypto.SHA256)))))
	err2.Check(headers.Set(jwe.ContentEncryptionKey, jwa.A256GCM))
	err2.Check(headers.Set(jwe.AlgorithmKey, jwa.ECDH_ES))

	clevis := try.To1(json.Marshal(&jsonClevis{
		Plugin: "tang",
		Tang: jsonTang{
			Location:      url,
			Advertisement: message.Payload(),
		},
	}))
	err2.Check(headers.Set("clevis", json.RawMessage(clevis)))

	return &Crypter{
		keyID:       thumbprint,
		headers:     headers,
		exchangeKey: exchangeKey,
	}, nil
}

func (c *Crypter) Encrypt(plain []byte) (cipher []byte, err error) {
	defer err2.Return(&err)
	return try.To1(jwe.Encrypt(plain, jwa.ECDH_ES, c.exchangeKey, jwa.A256GCM, jwa.NoCompress, jwe.WithProtectedHeaders(c.headers))), nil
}

func Decrypt(cipher []byte) (plain []byte, err error) {
	defer err2.Return(&err)
	return try.To1(clevis.Decrypt(cipher)), nil
}
