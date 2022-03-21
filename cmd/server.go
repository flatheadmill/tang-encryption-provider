package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bigeasy/tang-encryption-provider/plugin"
	//	"github.com/lainio/err2"
	"github.com/kelseyhightower/envconfig"
	"github.com/lainio/err2/try"
)

type Specification struct {
	ServerUrl  string `envconfig:"server_url"`
	Thumbprint string
	UnixSocket string `envconfig:"unix_socket" default:"/var/run/kmsplugin/socket.sock"`
}

func main() {
	var spec Specification
	try.To(envconfig.Process("tang_kms", &spec))
	fmt.Printf("%v %v\n", spec.Thumbprint, spec.UnixSocket)
	err := run(try.To1(plugin.New(spec.ServerUrl, spec.Thumbprint, spec.UnixSocket)))
	if err != nil {
		fmt.Printf("exited with error: %T %v\n", err, err)
	}
}

func run(plug *plugin.Plugin) error {
	signalsChannel := make(chan os.Signal, 1)
	signal.Notify(signalsChannel, syscall.SIGINT, syscall.SIGTERM)

	rpc, rpcErrorChannel := plug.ServeKMSRequests()
	if rpc != nil {
		defer rpc.GracefulStop()
	}

	for {
		select {
		case sig := <-signalsChannel:
			fmt.Printf("captured %v, shutting down kms-plugin\n", sig)
			return nil
		case err := <-rpcErrorChannel:
			return err
		}
	}
}
