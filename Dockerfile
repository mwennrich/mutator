FROM golang:1.26-alpine AS build
ENV GO111MODULE=on
ENV CGO_ENABLED=0


COPY . /app
WORKDIR /app

RUN apk add make binutils
RUN make mutator

FROM scratch

WORKDIR /

COPY --from=build /app/mutator .

ENTRYPOINT ["./mutator"]
