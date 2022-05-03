package main

import (
	"context"
	"fmt"
	"github.com/flatheadmill/tang-encryption-provider/api"
	"github.com/flatheadmill/tang-encryption-provider/crypter"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flatheadmill/tang-encryption-provider/logger"
	"github.com/flatheadmill/tang-encryption-provider/plugin"
	"github.com/kelseyhightower/envconfig"
	"github.com/lainio/err2/try"
)

type Specification struct {
	ServerUrl  string `envconfig:"server_url"`
	Thumbprint string
	UnixSocket string `envconfig:"unix_socket" default:"/var/run/kmsplugin/socket.sock"`
	HttpPort   string `envconfig:"http_port" default:"8081"`
}

func main() {
	var spec Specification
	try.To(envconfig.Process("tang_kms", &spec))
	log := logger.New(os.Stdout)
	log.Console()

	log.MsgWithFields(map[string]interface{}{"thumbprint": spec.Thumbprint, "unix_socket": spec.UnixSocket}, "")
	crypt := try.To1(crypter.NewCrypter(spec.ServerUrl, spec.Thumbprint))

	httpSvr := setupHttpServer([]HealthComponent{NewHealthComponent(crypt, "tang_crypter")}, spec.HttpPort)

	err := run(try.To1(plugin.New(crypt, spec.UnixSocket, log)), httpSvr)
	if err != nil {
		fmt.Printf("exited with error: %T %v\n", err, err)
	}
}

func run(plug *plugin.Plugin, api *http.Server) error {
	signalsCh := make(chan os.Signal, 1)
	signal.Notify(signalsCh, syscall.SIGINT, syscall.SIGTERM)

	rpc, rpcErrorChannel := plug.ServeKMSRequests()
	if rpc != nil {
		defer rpc.GracefulStop()
	}

	httpErrCh := startHttpServer(api)
	defer stopHttpServer(api)

	var err error
	select {
	case sig := <-signalsCh:
		fmt.Printf("captured %v, shutting down kms-plugin\n", sig)
	case err = <-rpcErrorChannel:
	case err = <-httpErrCh:
	}

	return err
}

func setupHttpServer(components []HealthComponent, httpPort string) *http.Server {
	compHealths := []api.ComponentHealth{}
	for _, comp := range components {
		compHealths = append(compHealths, api.ComponentHealth(comp))
	}
	healthAPI := api.NewHealthAPI(compHealths...)

	r := mux.NewRouter()
	r.HandleFunc("/livez", healthAPI.Health)
	r.HandleFunc("/readyz", healthAPI.Health)

	return &http.Server{Addr: ":" + httpPort, Handler: r}
}

func startHttpServer(httpSvr *http.Server) chan error {
	httpErrCh := make(chan error, 1)
	go func() {
		if err := httpSvr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			httpErrCh <- errors.Wrap(err, "http.ListenAndServe erred unexpectedly")
		}
	}()
	return httpErrCh
}

func stopHttpServer(httpSvr *http.Server) {
	// handle http server stop
	httpCtx, httpCancel := context.WithTimeout(context.Background(), time.Second*3)
	printErr(errors.Wrap(httpSvr.Shutdown(httpCtx), "failed to shutdown http server"))
	httpCancel()
}

func NewHealthComponent(component api.Healther, name string) HealthComponent {
	return HealthComponent{Healther: component, name: name}
}

type HealthComponent struct {
	api.Healther
	name string
}

func (h HealthComponent) Name() string {
	return h.name
}

func printErr(err error) bool {
	if err == nil {
		return false
	}
	fmt.Printf("%+v\n", err)
	return true
}
