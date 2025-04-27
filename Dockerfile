# ---
FROM --platform=$BUILDPLATFORM registry-1.docker.io/library/alpine:latest as certs
RUN apk update && apk add --no-cache ca-certificates

# ---
FROM --platform=$BUILDPLATFORM registry-1.docker.io/library/golang:1.24.2 as builder
WORKDIR /build/
COPY go.mod go.sum ./
RUN go mod download

ARG TARGETOS TARGETARCH VERSION
COPY . /build/

RUN --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg \
  CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -a -ldflags "-s -w -X main.version=${VERSION}" -o /out/auth-web3-htmx ./main.go

# ---
FROM registry-1.docker.io/library/busybox:1.37.0

ARG TARGETOS TARGETARCH

WORKDIR /app

COPY --from=builder /out/auth-web3-htmx .
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

USER 1000:1000

EXPOSE 3000

ENTRYPOINT ["/app/auth-web3-htmx"]
