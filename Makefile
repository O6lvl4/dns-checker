# DNS Checker - Makefile

BINARY_NAME := dns-checker
BUILD_DIR := _build/native/release/build/cmd/main
BINARY_FILE := $(BUILD_DIR)/main.exe
INSTALL_DIR := $(HOME)/.local/bin

.PHONY: all build run test clean install uninstall help

all: build

## Build the native binary
build:
	moon build --target native

## Run with a domain argument
run:
	@if [ -z "$(DOMAIN)" ]; then \
		moon run cmd/main --target native; \
	else \
		moon run cmd/main --target native -- $(DOMAIN); \
	fi

## Run tests
test:
	moon test --target native

## Clean build artifacts
clean:
	moon clean

## Install to ~/.local/bin
install: build
	@mkdir -p $(INSTALL_DIR)
	@cp $(BINARY_FILE) $(INSTALL_DIR)/$(BINARY_NAME)
	@chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installed $(BINARY_NAME) to $(INSTALL_DIR)"
	@echo "Make sure $(INSTALL_DIR) is in your PATH"

## Uninstall from ~/.local/bin
uninstall:
	@rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstalled $(BINARY_NAME)"

## Show help
help:
	@echo "DNS Checker - MoonBit Implementation"
	@echo ""
	@echo "Usage:"
	@echo "  make build      Build the native binary"
	@echo "  make run        Run without arguments (shows usage)"
	@echo "  make run DOMAIN=example.com  Run with a domain"
	@echo "  make test       Run tests"
	@echo "  make clean      Clean build artifacts"
	@echo "  make install    Install to ~/.local/bin"
	@echo "  make uninstall  Remove from ~/.local/bin"
	@echo ""
	@echo "After install:"
	@echo "  dns-checker example.com"
