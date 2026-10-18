BIN := skillisus

.PHONY: build i test lint clean

build:
	go build -o bin/$(BIN) .

i:
	go install .

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -rf bin
