set -e

echo --------------------------------------------------------------------------------

go build -o ../out/server server/server.go
go build -o ../out/encrypt encrypt/encrypt.go
go build -o ../out/decrypt decrypt/decrypt.go

export TANG_KMS_SERVER_URL=http://localhost:8080
export TANG_KMS_THUMBPRINT=QuUFrN0Ye4d31oEQ78j1eDHM6RXTu8hKr3Nk7tzLFdY
export TANG_KMS_UNIX_SOCKET=$HOME/dev/junk/socket

mkdir -p $HOME/dev/junk/
touch $TANG_KMS_UNIX_SOCKET

../out/server &

sleep 1

server=$!

echo hello | ../out/encrypt -grpc $HOME/dev/junk/socket | ../out/decrypt -grpc $HOME/dev/junk/socket
wait $server
