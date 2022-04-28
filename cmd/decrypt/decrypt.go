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

	"github.com/flatheadmill/tang-encryption-provider/crypter"
)

func decryptWithKMS(socket string) (err error) {
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

	plain := try.To1(client.Decrypt(ctx, &pb.DecryptRequest{Cipher: input}))

	fmt.Print(string(plain.Plain))

	return nil
}

func decryptWithTang() (err error) {
	defer err2.Return(&err)
	input := try.To1(ioutil.ReadAll(os.Stdin))
	plain := try.To1(crypter.Decrypt(input))
	fmt.Print(string(plain))
	return nil
}

func main() {
	var (
		grpc = flag.String("grpc", "", "url of gRPC server")
	)
	flag.Parse()
	var err error
	if *grpc != "" {
		err = decryptWithKMS(*grpc)
	} else {
		err = decryptWithTang()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
