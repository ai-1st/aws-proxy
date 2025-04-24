FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o aws-proxy ./cmd/aws-proxy

# Use a smaller image for the final container
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/aws-proxy .

# Create a volume for certificates
VOLUME ["/app/certs"]

# Expose the proxy port
EXPOSE 8080

# Run the proxy with default settings
ENTRYPOINT ["/app/aws-proxy", "--addr", ":8080", "--cert", "/app/certs/aws-proxy.crt", "--key", "/app/certs/aws-proxy.key", "--verbose", "true", "--permissive", "true"]
