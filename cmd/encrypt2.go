package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"

	pb "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

func run(socket string) (err error) {
	defer err2.Return(&err)

	input := try.To1(ioutil.ReadAll(os.Stdin))

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", addr)
	}

	conn := try.To1(grpc.Dial(socket, grpc.WithContextDialer(dialer), grpc.WithInsecure()))
	defer conn.Close()

	client := pb.NewKeyManagementServiceClient(conn)

	ctx := context.Background()

	version := try.To1(client.Version(ctx, &pb.VersionRequest{}))

	fmt.Fprintf(os.Stderr, "%v\n", version)

	cipher := try.To1(client.Encrypt(ctx, &pb.EncryptRequest{Plain: input}))

	fmt.Printf("%v\n", string(cipher.Cipher))

	return nil
}

func main() {
	var (
		url = flag.String("url", "", "url of gRPC server")
	)
	flag.Parse()
	err := run(*url)
	if err != nil {
		fmt.Fprintf(os.Stderr, ">> %v\n", err)
	}
}
