package main

import (
	"bytes"
	"crypto"
	"fmt"
	"os"
	"strings"

	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/lainio/err2"
	"io/ioutil"
	"math/big"
	"net/http"

	jose "github.com/go-jose/go-jose/v3"
	jcipher "github.com/go-jose/go-jose/v3/cipher"
)

func base64Decode(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

// dSize returns the size in octets for a coordinate on a elliptic curve.
func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / 8
	if bitLen%8 != 0 {
		size++
	}
	return size
}

func lengthPrefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}

// DeriveECDHES derives a shared encryption key using ECDH/ConcatKDF as described in JWE/JWA.
// It is an error to call this function with a private/public key that are not on the same
// curve. Callers must ensure that the keys are valid before calling this function. Output
// size may be at most 1<<16 bytes (64 KiB).
func DeriveECDHES(alg string, apuData, apvData []byte, pub *ecdsa.PublicKey, size int) []byte {
	if size > 1<<16 {
		panic("ECDH-ES output size too large, must be less than or equal to 1<<16")
	}

	// algId, partyUInfo, partyVInfo inputs must be prefixed with the length
	algID := lengthPrefixed([]byte(alg))
	ptyUInfo := lengthPrefixed(apuData)
	ptyVInfo := lengthPrefixed(apvData)

	// suppPubInfo is the encoded length of the output size in bits
	supPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(supPubInfo, uint32(size)*8)

	zBytes := pub.X.Bytes()

	// Note that calling z.Bytes() on a big.Int may strip leading zero bytes from
	// the returned byte array. This can lead to a problem where zBytes will be
	// shorter than expected which breaks the key derivation. Therefore we must pad
	// to the full length of the expected coordinate here before calling the KDF.
	octSize := dSize(pub.Curve)
	if len(zBytes) != octSize {
		zBytes = append(bytes.Repeat([]byte{0}, octSize-len(zBytes)), zBytes...)
	}

	reader := jcipher.NewConcatKDF(crypto.SHA256, zBytes, algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})
	key := make([]byte, size)

	// Read on the KDF will never fail
	_, _ = reader.Read(key)

	return key
}

type jsonTang struct {
	Location      string             `json:"url"`
	Advertisement jose.JSONWebKeySet `json:"adv"`
}

type jsonClevis struct {
	Plugin string   `json:"pin"`
	Tang   jsonTang `json:"tang"`
}

type jsonProtected struct {
	KeyIdentifier      string          `json:"kid"`
	Algorithm          string          `json:"alg"`
	Encryption         string          `json:"enc"`
	Clevis             jsonClevis      `json:"clevis"`
	EphemeralPublicKey jose.JSONWebKey `json:"epk"`
}

type Crypter struct {
}

func (c *Crypter) Decrypt(jwe string) ([]byte, error) {
	input := []byte(jwe)
	dot := bytes.IndexByte(input, byte('.'))
	header, err := base64.RawURLEncoding.DecodeString(string(input[0:dot]))

	protected := jsonProtected{}

	err = json.Unmarshal(header, &protected)
	err2.Check(err)

	var remote *ecdsa.PublicKey
	for _, key := range protected.Clevis.Tang.Advertisement.Keys {
		thumbprint, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			panic(err)
		}
		if protected.KeyIdentifier == base64.RawURLEncoding.EncodeToString(thumbprint) {
			remote = key.Key.(*ecdsa.PublicKey)
			break
		}
	}

	ephemeral, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	err2.Check(err)

	client := protected.EphemeralPublicKey.Key.(*ecdsa.PublicKey)
	x, y := elliptic.P521().Add(client.X, client.Y, ephemeral.X, ephemeral.Y)
	ecmr := jose.JSONWebKey{Key: &ecdsa.PublicKey{Curve: elliptic.P521(), X: x, Y: y}}
	ecmrJSON, err := json.Marshal(&ecmr)
	err2.Check(err)

	url := protected.Clevis.Tang.Location + "/rec/" + protected.KeyIdentifier
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(ecmrJSON))
	req.Header.Set("Content-Type", "application/jwk+json")

	agent := &http.Client{}
	post, err := agent.Do(req)
	err2.Check(err)
	defer post.Body.Close()

	body, err := ioutil.ReadAll(post.Body)
	err2.Check(err)

	var response jose.JSONWebKey
	err = json.Unmarshal(body, &response)
	err2.Check(err)

	// Calling big.Int.Bytes() strips leading zeros, so this could be a problem,
	// but the `D` value of `spec521r1` does not have any leading zeros.
	x, y = elliptic.P521().ScalarMult(remote.X, remote.Y, ephemeral.D.Bytes())

	negY := new(big.Int)
	negY.Sub(elliptic.P521().Params().P, y)
	x, y = elliptic.P521().Add(response.Key.(*ecdsa.PublicKey).X, response.Key.(*ecdsa.PublicKey).Y, x, negY)

	recovered := jose.JSONWebKey{Key: &ecdsa.PublicKey{Curve: elliptic.P521(), X: x, Y: y}}

	key := DeriveECDHES(protected.Encryption, []byte{}, []byte{}, recovered.Key.(*ecdsa.PublicKey), 32)

	parts := strings.Split(string(input), ".")
	if len(parts) != 5 {
		err2.Check(fmt.Errorf("compact JWE format must have five parts"))
	}

	iv, err := base64Decode(parts[2])
	err2.Check(err)

	ciphertext, err := base64Decode(parts[3])
	err2.Check(err)

	tag, err := base64Decode(parts[4])
	err2.Check(err)

	aeadCipher, err := aes.NewCipher(key)
	err2.Check(err)

	aead, err := cipher.NewGCM(aeadCipher)
	err2.Check(err)

	plaintext, err := aead.Open(nil, iv, append(ciphertext, tag...), []byte(parts[0]))
	err2.Check(err)

	return plaintext, nil
}

func main() {
	input, err := ioutil.ReadAll(os.Stdin)
	err2.Check(err)
	crypter := Crypter{}

	plaintext, err := crypter.Decrypt(string(input))

	fmt.Fprintf(os.Stderr, "%v\n", string(plaintext))
}
