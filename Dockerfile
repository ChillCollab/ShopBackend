FROM golang:1.21-alpine as builder

WORKDIR /Users/masev1ch/GolandProjects/ShopBackend

RUN apk --no-cache add bash git make gcc musl-dev gettext

RUN mkdir logs

COPY app/go.mod app/go.sum ./
RUN go mod download

# build
COPY app ./
RUN go build -o ./bin/app ./cmd/main.go

FROM alpine

COPY --from=builder /Users/masev1ch/GolandProjects/ShopBackend/languages /languages
COPY --from=builder /Users/masev1ch/GolandProjects/ShopBackend/bin/app /

CMD ["/app"]