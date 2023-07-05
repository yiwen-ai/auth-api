# options
ignore_output = &> /dev/null

.PHONY: run-dev test lint build docker

APP_NAME := auth-api
APP_PATH := github.com/yiwen-ai/auth-api
APP_VERSION := $(shell git describe --tags --always --match "v[0-9]*")
BUILD_TIME := $(shell date -u +"%FT%TZ")
BUILD_COMMIT := $(shell git rev-parse HEAD)
DOCKER_IMAGE_TAG := yiwen-ai/${APP_NAME}:latest

run-dev:
	@CONFIG_FILE_PATH=${PWD}/config.toml APP_ENV=dev go run main.go

test:
	@CONFIG_FILE_PATH=${PWD}/config/test.yml APP_ENV=test go test ./...

lint:
	@hash golint > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		go get -u golang.org/x/lint/golint; \
	fi
	@golint -set_exit_status ${PKG_LIST}

build:
	@mkdir -p ./dist
	go build -ldflags "-X ${APP_PATH}/src/conf.AppName=${APP_NAME} \
	-X ${APP_PATH}/src/conf.AppVersion=${APP_VERSION} \
	-X ${APP_PATH}/src/conf.BuildTime=${BUILD_TIME} \
	-X ${APP_PATH}/src/conf.GitSHA1=${BUILD_COMMIT}" \
	-o ./dist/auth-api main.go

docker:
	@docker build --rm -t ${DOCKER_IMAGE_TAG} .
