package plugin

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"

	"github.com/flatheadmill/tang-encryption-provider/handler"
)

const (
	netProtocol    = "unix"
	apiVersion     = "v1beta1"
	runtimeName    = "TangKMS"
	runtimeVersion = "0.0.1"

	statusSuccess    = "success"
	statusFailure    = "failure"
	operationEncrypt = "encrypt"
	operationDecrypt = "decrypt"
)

type Crypter interface {
	Encrypt(plain []byte) (cipher []byte, err error)
	Decrypt(cipher []byte) (plain []byte, err error)
}

type Plugin struct {
	crypter Crypter
	socket  string
	logger  logger
	net.Listener
	*grpc.Server
}

type logger interface {
	Msg(msg string)
	Msgf(format string, a ...any)
	MsgWithFields(fields map[string]interface{}, msg string)
	Err(err error) bool
}

type LogFields map[string]interface{}

func New(l logger, crypter Crypter, socket string) (plugin *Plugin, err error) {
	defer err2.Handle(&err, handler.Handler(&err))

	return &Plugin{crypter: crypter, socket: socket, logger: l}, nil
}

func (p *Plugin) Version(ctx context.Context, request *VersionRequest) (*VersionResponse, error) {
	return &VersionResponse{Version: apiVersion, RuntimeName: runtimeName, RuntimeVersion: runtimeVersion}, nil
}

func (p *Plugin) Health() error {
	randomPlaintext := randomHex(8)
	encryptResp, err := p.Encrypt(context.Background(), &EncryptRequest{Plain: []byte(randomPlaintext)})
	if err != nil {
		return errors.Wrap(err, "failed to encrypt random text")
	}

	decryptResp, err := p.Decrypt(context.Background(), &DecryptRequest{Cipher: encryptResp.GetCipher()})
	if err != nil {
		return errors.Wrap(err, "failed to decrypt random text cipher")
	}
	if randomPlaintext != string(decryptResp.GetPlain()) {
		return errors.Errorf("decrypted text does not equal input random text: want: %s got: %s", randomPlaintext, decryptResp.GetPlain())
	}
	return nil
}

// TODO Notify only of error and add metrics.
func (p *Plugin) Encrypt(ctx context.Context, request *EncryptRequest) (response *EncryptResponse, err error) {
	sTime := time.Now()
	defer func() {
		status := statusSuccess
		if err != nil {
			status = statusFailure
		}
		// TODO: write/use interface for metrics or
		// 	Maybe write wrapper for plugin Encrypt/Decrypt that handles metrics/logging separately.
		kmsOperationCounter.WithLabelValues(status, operationEncrypt).Inc()
		kmsLatencyMetric.WithLabelValues(status, operationEncrypt).Observe(msSince(sTime))
	}()
	var cipher []byte
	cipher, err = p.crypter.Encrypt(request.Plain)
	err = errors.Wrap(err, "failed to encrypt")

	if !p.logger.Err(err) {
		p.logger.MsgWithFields(LogFields{"jwe": string(cipher)}, "encrypted")
	}

	return &EncryptResponse{Cipher: cipher}, err
}

// TODO Notify only of error and add metrics.
func (p *Plugin) Decrypt(ctx context.Context, request *DecryptRequest) (response *DecryptResponse, err error) {
	sTime := time.Now()
	defer func() {
		status := statusSuccess
		if err != nil {
			status = statusFailure
		}
		// TODO: write/use interface for metrics or
		// 	Maybe write wrapper for plugin Encrypt/Decrypt that handles metrics/logging separately.
		kmsOperationCounter.WithLabelValues(status, operationDecrypt).Inc()
		kmsLatencyMetric.WithLabelValues(status, operationDecrypt).Observe(msSince(sTime))
	}()
	p.logger.MsgWithFields(LogFields{"jwe": string(request.Cipher)}, "decrypting")
	var plain []byte
	plain, err = crypter.Decrypt(request.Cipher)
	err = errors.Wrap(err, "failed to decrypt")
	p.logger.Err(err)
	return &DecryptResponse{Plain: plain}, err
}

func (p *Plugin) setupRPCServer() (err error) {
	defer err2.Handle(&err, handler.Handler(&err))

	// @ implies the use of Linux socket namespace - no file on disk and nothing
	// to clean-up.
	if !strings.HasPrefix(p.socket, "@") {
		try.To(func() error {
			err = os.Remove(p.socket)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}())
	}

	p.Listener = try.To1(net.Listen(netProtocol, p.socket))
	p.logger.Msgf("Listening on unix domain socket: %s", p.socket)

	p.Server = grpc.NewServer()
	RegisterKeyManagementServiceServer(p.Server, p)

	return nil
}

func (p *Plugin) ServeKMSRequests() (*grpc.Server, chan error) {
	errorChannel := make(chan error, 1)

	if err := p.setupRPCServer(); err != nil {
		errorChannel <- err
		close(errorChannel)
		return nil, errorChannel
	}

	go func() {
		defer close(errorChannel)
		errorChannel <- p.Serve(p.Listener)
	}()

	return p.Server, errorChannel
}

func msSince(startTime time.Time) float64 {
	return time.Since(startTime).Seconds() * 1000
}
func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomHex(n int) string {
	if n <= 0 {
		return ""
	}
	buf := make([]byte, (n/2)+(n%2))
	if _, err := cryptoRand.Read(buf); err != nil {
		fmt.Println(err)
		return ""
	}
	return hex.EncodeToString(buf)[:n]
}
