FROM golang as builder

WORKDIR /go/src/app
COPY . .

RUN go build -o smokescreen .

FROM alpine:3.20.1

COPY --from=builder /go/src/app/smokescreen /usr/local/bin/smokescreen

RUN apk add --no-cache gcompat

EXPOSE 4750

CMD ["smokescreen"]