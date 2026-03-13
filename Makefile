.PHONY: test lint vet fmt map-uts

test:
	go test ./... -coverprofile cover.out

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

map-uts:
	@./script/map-uts.sh
