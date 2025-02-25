# Build container
FROM docker.io/library/golang:1.24.0-alpine AS builder

WORKDIR /go/src/k8s_crlish_authorizer
COPY go.mod go.sum .
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build \
  -a -tags netgo -ldflags '-w -extldflags "-static"' \
  -o k8s_crlish_authorizer_server

# Runtime container
FROM scratch

WORKDIR /
COPY --from=builder /go/src/k8s_crlish_authorizer/k8s_crlish_authorizer_server .

USER 10000
ENTRYPOINT ["/k8s_crlish_authorizer_server"]

EXPOSE 8443
