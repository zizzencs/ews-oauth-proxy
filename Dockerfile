FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o ews-oauth-proxy .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata openssl bash

WORKDIR /app
COPY --from=builder /app/ews-oauth-proxy .
COPY generate-cert.sh .
RUN chmod +x generate-cert.sh && mkdir -p certs

EXPOSE 8443

CMD ["./ews-oauth-proxy"]
