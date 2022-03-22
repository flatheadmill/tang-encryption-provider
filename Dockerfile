FROM golang:1.18 AS build

WORKDIR /app

COPY . ./

RUN find .
# CGO_ENABLED=0 ~ https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
RUN mkdir -p /app/out && cd /app/cmd && CGO_ENABLED=0 go build -o ../out/server server.go

FROM alpine

WORKDIR /

COPY --from=build /app/out/server /usr/local/bin/tang-encryption-provider

RUN addgroup nonroot && adduser -G nonroot -D nonroot

# USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/tang-encryption-provider"]
