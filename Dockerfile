FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /soju-admin .

# Runs as root on purpose: at startup it switches to the owner of soju.db
# (so WAL/backup files stay writable by soju) before serving anything.
FROM gcr.io/distroless/static-debian12
COPY --from=build /soju-admin /soju-admin
EXPOSE 8090
ENTRYPOINT ["/soju-admin"]
