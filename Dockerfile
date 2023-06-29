FROM golang:1.20 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/cainjector *.go

FROM debian:bullseye-slim AS app

COPY --from=builder /bin/cainjector /bin/cainjector

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/cainjector"]
