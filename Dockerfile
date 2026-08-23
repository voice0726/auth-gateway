FROM golang:1.25.5-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o /out/auth-gateway ./cmd/server

FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/auth-gateway /app/auth-gateway
COPY --from=builder /src/config /app/config

ENV CONFIG_PATH=/app/config/dev.yaml

EXPOSE 8800

USER nonroot:nonroot

ENTRYPOINT ["/app/auth-gateway"]
