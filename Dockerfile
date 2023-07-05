# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:latest AS builder

WORKDIR /src
COPY config ./config
COPY keys ./keys
COPY src ./src
COPY go.mod go.sum main.go Makefile ./
RUN make build

FROM --platform=$BUILDPLATFORM ubuntu:23.04
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone
RUN apt-get update \
    && apt-get install -y bash curl ca-certificates tzdata locales \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

WORKDIR /app
COPY --from=builder /src/config ./config
COPY --from=builder /src/keys ./keys
COPY --from=builder /src/dist/auth-api ./
ENTRYPOINT ["./auth-api"]
