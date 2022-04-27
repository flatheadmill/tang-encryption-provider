set -e

echo --------------------------------------------------------------------------------

go build -o ../out/server server.go
go build -o ../out/encrypt2 encrypt2.go
go build -o ../out/decrypt2 decrypt2.go

export TANG_KMS_SERVER_URL=http://tang:8080
export TANG_KMS_THUMBPRINT=o6U9qKv0_XdugefJV3q_NknYTY4Xgw27kcUnErkrVCY
export TANG_KMS_UNIX_SOCKET=$HOME/junk/socket

../out/server &

sleep 1

server=$!

echo hello | ../out/encrypt2 --url $HOME/junk/socket | ../out/decrypt2 --url $HOME/junk/socket

wait $server
