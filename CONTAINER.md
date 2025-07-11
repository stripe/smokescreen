# Container Image Usage

This project provides pre-built container images for smokescreen that are automatically built and published to GitHub Container Registry.

## Available Images

The container images are available at:
- `ghcr.io/stripe/smokescreen:latest` - Latest release

## Supported Platforms

- `linux/amd64` - Intel/AMD 64-bit
- `linux/arm64` - ARM 64-bit

## Running the Container

### Basic Usage

```bash
docker run -p 4750:4750 ghcr.io/stripe/smokescreen:latest  --listen-ip 0.0.0.0 --listen-port 4750
```

Smokescreen can then be used like in `curl --proxy localhost:4750 http://example.com`.

## Verification

To verify the image signature:

```bash
cosign verify ghcr.io/stripe/smokescreen:latest \
  --certificate-identity-regexp="https://github.com/stripe/smokescreen" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

## Building Locally

To build the container image outside of CI:

```bash
# Install ko
go install github.com/ko-build/ko@latest

# Build for multiple platforms
ko build . --platform=linux/amd64,linux/arm64 --local
```
