PLATFORM=$(shell uname -s | tr '[:upper:]' '[:lower:]')
VERSION := $(shell grep -Eo '(v[0-9]+[\.][0-9]+[\.][0-9]+(-[a-zA-Z0-9]*)?)' version.go)

.PHONY: check
check:
ifeq ($(OS),Windows_NT)
	go test ./...
else
	@wget -O lint-project.sh https://raw.githubusercontent.com/moov-io/infra/master/go/lint-project.sh
	@chmod +x ./lint-project.sh
	COVER_THRESHOLD=50.0 ./lint-project.sh
endif

dist: clean
ifeq ($(OS),Windows_NT)
	CGO_ENABLED=1 GOOS=windows go build -o bin/tr31.exe github.com/moov-io/tr31/cmd/tr31
else
	CGO_ENABLED=1 GOOS=$(PLATFORM) go build -o bin/tr31-$(PLATFORM)-amd64 github.com/moov-io/tr31/cmd/tr31
endif

.PHONY: setup
setup:
	docker compose up -d --force-recreate --remove-orphans

.PHONY: teardown
teardown:
	-docker compose down --remove-orphans

.PHONY: clean
clean:
	@rm -rf ./bin/ ./tmp/ coverage.txt misspell* staticcheck lint-project.sh

.PHONY: cover-test cover-web
cover-test:
	go test -coverprofile=cover.out ./...
cover-web:
	go tool cover -html=cover.out
