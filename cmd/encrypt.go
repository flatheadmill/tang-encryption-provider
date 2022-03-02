package main

import (
    "crypto"
    "fmt"

    "encoding/base64"
    "encoding/json"
    "io/ioutil"
    "net/http"

    "github.com/lainio/err2"
    jose "github.com/go-jose/go-jose/v3"
)

type Tang struct {
    Location string `json:"url"`
    Advertisement jose.JSONWebKeySet `json:"adv"`
}

type Clevis struct {
    Plugin string `json:"pin"`
    Tang Tang `json:"tang"`
}

type Protected struct {
    KeyIdentifier string `json:"kid"`
    Algorithm string `json:"alg"`
    Encryption string `json:"enc"`
    Clevis Clevis `json:"clevis"`
    EphemeralPublicKey jose.JSONWebKey `json:"epk"`
}

const Thumbprint = "o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY"

func main () {
    // TODO Trust on first use or thumbprint?
    advGet, err := http.Get("http://tang:8080/adv/" + Thumbprint)
    err2.Check(err)
    defer advGet.Body.Close()
    advJSON, err := ioutil.ReadAll(advGet.Body)
    var adv map[string]interface{}
    err = json.Unmarshal(advJSON, &adv)
    err2.Check(err)
    payload, err := base64.RawURLEncoding.DecodeString(adv["payload"].(string))
    err2.Check(err)
    var keySet jose.JSONWebKeySet
    err = json.Unmarshal(payload, &keySet)
    err2.Check(err)
    var deriver *jose.JSONWebKey
    Keys: for _, key := range keySet.Keys {
        for _, op := range key.KeyOps {
            if op == "deriveKey" {
                deriver = &key
                break Keys
            }
        }
    }
    deriver.Algorithm = ""
    deriver.KeyOps = nil
    err2.Check(err)
    extraHeaders := make(map[jose.HeaderKey]interface{})
    thumbprint, err := deriver.Thumbprint(crypto.SHA256)
    err2.Check(err)
    extraHeaders["kid"] = base64.RawURLEncoding.EncodeToString(thumbprint)
    tang := Tang{
        Location: "http://tang:8080",
        Advertisement: keySet,
    }
    clevis := Clevis{
        Plugin: "tang",
        Tang: tang,
    }
    extraHeaders["clevis"] = clevis
    encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: deriver.Key},
        &jose.EncrypterOptions{
            ExtraHeaders: extraHeaders,
        })
    err2.Check(err)
    cipher, err := encrypter.Encrypt([]byte("hi\n"))
    err2.Check(err)
    compact, err := cipher.CompactSerialize()
    err2.Check(err)
    fmt.Println(compact)
}
