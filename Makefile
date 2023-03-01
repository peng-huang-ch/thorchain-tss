module = gitlab.com/thorchain/tss/go-tss

.PHONY: clear tools install test test-watch lint-pre lint lint-verbose protob build docker-gitlab-login docker-gitlab-push docker-gitlab-build samples

all: lint build

clear:
	clear

tools:
	go install ./cmd/tss-recovery
	go install ./cmd/tss-benchgen
	go install ./cmd/tss-benchsign

install: go.sum
	go install ./cmd/tss

go.sum: go.mod
	@echo "--> Ensure dependencies have not been modified"
	go mod verify

test:
	@go test --race ./...

test-watch: clear
	@gow -c test -tags testnet -mod=readonly ./...

unittest:
	@go test --race -v -coverprofile=coverage.out -timeout 15m ./...
	@go tool cover -func=coverage.out

lint-pre:
	@gofumpt -l cmd common keygen keysign messages p2p storage tss # for display
	@test -z "$(shell gofumpt -l cmd common keygen keysign messages p2p storage tss)" # cause error
	@go mod verify

lint: lint-pre
	@golangci-lint run

lint-verbose: lint-pre
	@golangci-lint run -v

protob:
	protoc --go_out=module=$(module):. ./messages/*.proto

build: protob
	go build ./...

docker-build:
	docker build -t registry.gitlab.com/thorchain/tss/go-tss .

samples: client-1 client-2 client-3

client-1:	
	@echo "[client-1] Starting server..."
	@go run cmd/tss/tss_http.go cmd/tss/main.go -tss-port :9080 -p2p-port 6668 -loglevel debug --priv-key "ZThiMDAxOTk2MDc4ODk3YWE0YThlMjdkMWY0NjA1MTAwZDgyNDkyYzdhNmMwZWQ3MDBhMWIyMjNmNGMzYjVhYg==" --home "./data/client1"

client-2:
	@echo "[client-2] Starting server..."
	@go run cmd/tss/tss_http.go cmd/tss/main.go -tss-port :9081 -p2p-port 6678 -loglevel debug -peer "/ip4/127.0.0.1/tcp/6668/ipfs/16Uiu2HAm4TmEzUqy3q3Dv7HvdoSboHk5sFj2FH3npiN5vDbJC6gh" --priv-key "ZTc2ZjI5OTIwOGVlMDk2N2M3Yzc1MjYyODQ0OGUyMjE3NGJiOGRmNGQyZmVmODg0NzQwNmUzYTk1YmQyODlmNA==" --home "./data/client2"

client-3:
	@echo "[client-3] Starting server..."
	@go run cmd/tss/tss_http.go cmd/tss/main.go -tss-port :9082 -p2p-port 6688 -loglevel debug -peer "/ip4/127.0.0.1/tcp/6668/ipfs/16Uiu2HAm4TmEzUqy3q3Dv7HvdoSboHk5sFj2FH3npiN5vDbJC6gh" --priv-key "MjQ1MDc2MmM4MjU5YjRhZjhhNmFjMmI0ZDBkNzBkOGE1ZTBmNDQ5NGI4NzM4OTYyM2E3MmI0OWMzNmE1ODZhNw==" --home "./data/client3"

client-4:
	@echo "[client-3] Starting server..."
	go run cmd/tss/tss_http.go cmd/tss/main.go -tss-port :9083 -p2p-port 6698 -loglevel debug -peer "/ip4/127.0.0.1/tcp/6668/ipfs/16Uiu2HAm4TmEzUqy3q3Dv7HvdoSboHk5sFj2FH3npiN5vDbJC6gh" --priv-key "YmNiMzA2ODU1NWNjMzk3NDE1OWMwMTM3MDU0NTNjN2YwMzYzZmVhZDE5NmU3NzRhOTMwOWIxN2QyZTQ0MzdkNg==" --home "./data/client4"

kill-samples:
	pkill -f ":(9080|9081|9082)"