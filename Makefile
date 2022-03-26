build:
	mkdir -p out/server
	CGO_ENABLED=0 go build -o out/server cmd/server.go
	CGO_ENABLED=0 go build -o out/encrypt cmd/encrypt.go
	CGO_ENABLED=0 go build -o out/decrypt cmd/decrypt.go
