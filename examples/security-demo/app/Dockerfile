# syntax=docker/dockerfile:1.18
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

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
