#!/bin/bash

# Exit on any error
set -e

echo "Building ews-oauth-proxy for multiple platforms..."

# Linux (Current architecture)
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o ews-oauth-proxy .

# Linux ARM64
echo "Building for Linux (ARM64)..."
GOOS=linux GOARCH=arm64 go build -o ews-oauth-proxy-linux-arm64 .

# macOS Intel
echo "Building for macOS (Intel amd64)..."
GOOS=darwin GOARCH=amd64 go build -o ews-oauth-proxy-macos-intel .

# macOS Apple Silicon
echo "Building for macOS (Apple arm64)..."
GOOS=darwin GOARCH=arm64 go build -o ews-oauth-proxy-macos-arm64 .

# Windows
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o ews-oauth-proxy.exe .

echo "Building for Windows (ARM64)..."
GOOS=windows GOARCH=arm64 go build -o ews-oauth-proxy-arm64.exe .

echo "Build complete! The following binaries were generated:"
ls -lh ews-oauth-proxy ews-oauth-proxy-linux-arm64 ews-oauth-proxy-macos-intel ews-oauth-proxy-macos-arm64 ews-oauth-proxy.exe ews-oauth-proxy-arm64.exe
