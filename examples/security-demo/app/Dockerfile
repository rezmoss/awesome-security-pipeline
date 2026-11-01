# syntax=docker/dockerfile:1.18
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

WORKDIR /src
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY main.go main_test.go ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    go test ./...
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/security-demo .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/security-demo /security-demo
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/security-demo"]
