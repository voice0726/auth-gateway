FROM golang:1.27.3-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o /out/auth-gateway ./cmd/server

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o /out/cleanup ./cmd/cleanup

FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/auth-gateway /app/auth-gateway
COPY --from=builder /out/migrate /app/migrate
COPY --from=builder /out/cleanup /app/cleanup
EXPOSE 8800

USER nonroot:nonroot

ENTRYPOINT ["/app/auth-gateway"]
