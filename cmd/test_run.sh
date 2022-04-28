set -e

echo --------------------------------------------------------------------------------

go build -o ../out/server server/server.go
go build -o ../out/encrypt encrypt/encrypt.go
go build -o ../out/decrypt decrypt/decrypt.go

export TANG_KMS_SERVER_URL=http://localhost:8080
export TANG_KMS_THUMBPRINT=$(curl -s $TANG_KMS_SERVER_URL/adv | jq -r '.payload' | base64 --decode | jq '.keys[0]' | jose jwk thp -i -)
export TANG_KMS_UNIX_SOCKET=$HOME/dev/junk/socket

mkdir -p $(dirname $TANG_KMS_UNIX_SOCKET)
touch $TANG_KMS_UNIX_SOCKET

../out/server &

sleep 1

server=$!

echo hello | ../out/encrypt -grpc $TANG_KMS_UNIX_SOCKET | ../out/decrypt -grpc $TANG_KMS_UNIX_SOCKET
wait $server
