# Copyright (c) 2026 Florian Fischer
#
# Use of this source code is governed by the MIT license found in the
# LICENSE file in the project root.

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/spcert-fetch .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=builder /out/spcert-fetch /usr/local/bin/spcert-fetch
USER app
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/spcert-fetch"]
