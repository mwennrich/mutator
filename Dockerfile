FROM golang:1.20-alpine AS build
ENV GO111MODULE=on
ENV CGO_ENABLED=0


COPY . /app
WORKDIR /app

RUN apk add make binutils
RUN make general-mutator

FROM alpine

WORKDIR /

COPY --from=build /app .

ENTRYPOINT ["./general-mutator"]
