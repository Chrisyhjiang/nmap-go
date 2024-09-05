# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=nmap-go
BINARY_UNIX=$(BINARY_NAME)_unix

# Main package path
MAIN_PACKAGE=./cmd/nmap-go

# Binary directory
BIN_DIR=bin

# Default target will run tidy, clean, and build
all: tidy clean build

# Build target depends on tidy and clean
build:
	mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(BIN_DIR)/$(BINARY_NAME) -v $(MAIN_PACKAGE)

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -rf $(BIN_DIR)

tidy:
	$(GOMOD) tidy

deps:
	$(GOGET) github.com/google/gopacket
	$(GOGET) github.com/google/gopacket/pcap
	$(GOGET) github.com/google/gopacket/layers

# Cross compilation
build-linux:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BIN_DIR)/$(BINARY_UNIX) -v $(MAIN_PACKAGE)

# Run with sudo (for SYN scans)
run-sudo: build
	sudo ./$(BIN_DIR)/$(BINARY_NAME)

.PHONY: all build test clean run tidy deps build-linux run-sudo
