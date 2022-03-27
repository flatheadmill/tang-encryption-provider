package plugin

import (
	"context"
	"fmt"
	"github.com/francoispqt/onelog"
	"net"
	"os"
	"strings"

	"github.com/flatheadmill/tang-encryption-provider/crypter"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
)

const (
	netProtocol    = "unix"
	apiVersion     = "v1beta1"
	runtimeName    = "TangKMS"
	runtimeVersion = "0.0.1"
)

type Plugin struct {
	crypter *crypter.Crypter
	socket  string
	logger  *onelog.Logger
	net.Listener
	*grpc.Server
}

func New(url string, thumbprint string, socket string, logger *onelog.Logger) (plugin *Plugin, err error) {
	defer err2.Return(&err)
	crypt := try.To1(crypter.NewCrypter(url, thumbprint))
	return &Plugin{crypter: crypt, socket: socket, logger: logger}, nil
}

func (g *Plugin) Version(ctx context.Context, request *VersionRequest) (*VersionResponse, error) {
	return &VersionResponse{Version: apiVersion, RuntimeName: runtimeName, RuntimeVersion: runtimeVersion}, nil
}

func (g *Plugin) Encrypt(ctx context.Context, request *EncryptRequest) (response *EncryptResponse, err error) {
	defer err2.Return(&err)
	// TODO This is just to ensure that things are working correctly in
	// Kubernetes, then we delete this.
	g.logger.InfoWithFields("encrypting", func(e onelog.Entry) { e.String("plain", string(request.Plain)) })
	cipher := try.To1(g.crypter.Encrypt(request.Plain))
	g.logger.InfoWithFields("encrypted", func(e onelog.Entry) { e.String("jwe", string(cipher)) })
	return &EncryptResponse{Cipher: []byte(cipher)}, nil
}

func (g *Plugin) Decrypt(ctx context.Context, request *DecryptRequest) (response *DecryptResponse, err error) {
	defer err2.Return(&err)
	g.logger.InfoWithFields("decrypting", func(e onelog.Entry) { e.String("jwe", string(request.Cipher)) })
	plain := try.To1(crypter.Decrypt(request.Cipher))
	// TODO This is just to ensure that things are working correctly in
	// Kubernetes, then we delete this.
	g.logger.InfoWithFields("decrypted", func(e onelog.Entry) { e.String("plain", string(plain)) })
	return &DecryptResponse{Plain: []byte(plain)}, nil
}

func (g *Plugin) setupRPCServer() (err error) {
	defer err2.Return(&err)

	// @ implies the use of Linux socket namespace - no file on disk and nothing
	// to clean-up.
	if !strings.HasPrefix(g.socket, "@") {
		try.To(func() error {
			err = os.Remove(g.socket)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}())
	}

	g.Listener = try.To1(net.Listen(netProtocol, g.socket))
	g.logger.Info(fmt.Sprintf("Listening on unix domain socket: %s", g.socket))

	g.Server = grpc.NewServer()
	RegisterKeyManagementServiceServer(g.Server, g)

	return nil
}

func (g *Plugin) ServeKMSRequests() (*grpc.Server, chan error) {
	errorChannel := make(chan error, 1)

	if err := g.setupRPCServer(); err != nil {
		errorChannel <- err
		close(errorChannel)
		return nil, errorChannel
	}

	go func() {
		defer close(errorChannel)
		errorChannel <- g.Serve(g.Listener)
	}()

	return g.Server, errorChannel
}
