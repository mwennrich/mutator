FROM golang:1.23-alpine AS build
ENV GO111MODULE=on
ENV CGO_ENABLED=0


COPY . /app
WORKDIR /app

RUN apk add make binutils
RUN make mutator

FROM alpine

WORKDIR /

COPY --from=build /app .

ENTRYPOINT ["./mutator"]
