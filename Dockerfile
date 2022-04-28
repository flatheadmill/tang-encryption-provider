# syntax=docker/dockerfile:1.3-labs
FROM golang:1.18 AS build

WORKDIR /app

COPY . ./

RUN find .
# CGO_ENABLED=0 ~ https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
RUN mkdir -p /app/out \
  && cd /app/cmd \
  && CGO_ENABLED=0 go build -o ../out/server server/server.go \
  && CGO_ENABLED=0 go build -o ../out/encrypt encrypt/encrypt.go \
  && CGO_ENABLED=0 go build -o ../out/decrypt decrypt/decrypt.go

FROM alpine

WORKDIR /

COPY --from=build /app/out/server /usr/local/bin/tang-encryption-provider
COPY --from=build /app/out/encrypt /usr/local/bin/encrypt
COPY --from=build /app/out/decrypt /usr/local/bin/decrypt

RUN addgroup nonroot && adduser -G nonroot -D nonroot

RUN apk update && apk add bind-tools

# USER nonroot:nonroot

# ENTRYPOINT ["/usr/local/bin/tang-encryption-provider"]
