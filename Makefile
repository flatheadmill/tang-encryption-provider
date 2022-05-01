build:
	mkdir -p out
	CGO_ENABLED=0 go build -o out/server cmd/server/server.go
	CGO_ENABLED=0 go build -o out/encrypt cmd/encrypt/encrypt.go
	CGO_ENABLED=0 go build -o out/decrypt cmd/decrypt/decrypt.go
