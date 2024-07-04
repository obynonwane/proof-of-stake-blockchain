#  Used testify for test assertion
#  go get github.com/stretchr/testify


build:
	@go build -o bin/blocker

run: build
	@./bin/blocker

test:
	@go test -v ./...