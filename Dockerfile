FROM golang:1.21 as builder

ARG CGO_ENABLED=0

WORKDIR /usr/app

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o server

FROM scratch

COPY --from=builder /usr/app/server /app

EXPOSE 8080

ENTRYPOINT ["/app"]