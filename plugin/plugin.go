package plugin

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/bigeasy/tang-encryption-provider/crypter"
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
	net.Listener
	*grpc.Server
}

func New(url string, thumbprint string, socket string) (plugin *Plugin, err error) {
	defer err2.Return(&err)
	crypt := try.To1(crypter.NewCrypter(url, thumbprint))
	return &Plugin{crypter: &crypt, socket: socket}, nil
}

func (g *Plugin) Version(ctx context.Context, request *VersionRequest) (*VersionResponse, error) {
	return &VersionResponse{Version: apiVersion, RuntimeName: runtimeName, RuntimeVersion: runtimeVersion}, nil
}

func (g *Plugin) Encrypt(ctx context.Context, request *EncryptRequest) (response *EncryptResponse, err error) {
	defer err2.Return(&err)
	cipher := try.To1(g.crypter.Encrypt(request.Plain))
	return &EncryptResponse{Cipher: []byte(cipher)}, nil
}

func (g *Plugin) Decrypt(ctx context.Context, request *DecryptRequest) (response *DecryptResponse, err error) {
	defer err2.Return(&err)
	plain := try.To1(crypter.Decrypt(request.Cipher))
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
	fmt.Printf("Listening on unix domain socket: %s\n", g.socket)

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
