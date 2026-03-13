.PHONY: test lint vet fmt

test:
	go test ./... -coverprofile cover.out

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	go fmt ./...
