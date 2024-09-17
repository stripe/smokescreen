
# Development and Testing

## Testing
```bash
go test ./...
```

## Running locally

This section describes how to run Smokescreen locally with different scenarios and using `curl` as a client.

- [HTTP Proxy](#http-proxy)
- [HTTP CONNECT Proxy](#http-connect-proxy)
- [Monitor metrics Smokescreen emits](#monitor-metrics-smokescreen-emits)
- [HTTP CONNECT Proxy over TLS](#http-connect-proxy-over-tls)
- [MITM (Man in the middle) Proxy](#mitm-man-in-the-middle-proxy)
- [MITM (Man in the middle) Proxy over TLS](#mitm-man-in-the-middle-proxy-over-tls)

### HTTP Proxy

#### Configurations

```yaml
# config.yaml
---
allow_missing_role: true  # skip mTLS client validation (use default ACL)
```

```yaml
# acl.yaml
---
version: v1
services: []
default:
  name: default
  project: security
  action: enforce
  allowed_domains: 
    - example.com
```

#### Run

```bash
# Run smokescreen (in a different shell)
go run . --config-file config.yaml --egress-acl-file acl.yaml

# Curl
curl -x localhost:4750 http://example.com
# Curl with ALL_PROXY
ALL_PROXY=localhost:4750 curl -v http://example.com
```

### HTTP CONNECT Proxy

#### Configurations

```yaml
# config.yaml
---
allow_missing_role: true  # skip mTLS client validation (use default ACL)
```

```yaml
# acl.yaml
---
version: v1
services: []
default:
  name: default
  project: security
  action: enforce
  allowed_domains: 
    - api.github.com
```

#### Run

```bash
# Run smokescreen (in a different shell)
go run . --config-file config.yaml --egress-acl-file acl.yaml

# Curl
curl --proxytunnel -x localhost:4750 https://api.github.com/zen
# Curl with HTTPS_PROXY
HTTPS_PROXY=localhost:4750 curl https://api.github.com/zen
```

### Monitor metrics Smokescreen emits

#### Configurations

```yaml
# config.yaml
---
allow_missing_role: true  # skip mTLS client validation (use default ACL)
statsd_address: 127.0.0.1:8200
```

```yaml
# acl.yaml
---
version: v1
services: []
default:
  name: default
  project: security
  action: enforce
  allowed_domains: 
    - api.github.com
```

#### Run

```bash
# Listen to a local port with nc (in a different shell)
nc -uklv 127.0.0.1 8200

# Run smokescreen (in a different shell)
go run . --config-file config.yaml --egress-acl-file acl.yaml

# Curl
curl --proxytunnel -x localhost:4750 https://api.github.com/zen
# Curl with HTTPS_PROXY
HTTPS_PROXY=localhost:4750 curl https://api.github.com/zen
```

### HTTP CONNECT Proxy over TLS

#### Set-up

##### Generate certificates
```bash
mkdir -p mtls_setup
# Private keys for CAs
openssl genrsa -out mtls_setup/server-ca.key 2048
openssl genrsa -out mtls_setup/client-ca.key 2048

# Generate client and server CA certificates
openssl req -new -x509 -nodes -days 1000 -key mtls_setup/server-ca.key -out mtls_setup/server-ca.crt \
    -subj "/C=AQ/ST=Petrel Island/L=Dumont-d'Urville
/O=Penguin/OU=Publishing house/CN=server CA"
    
openssl req -new -x509 -nodes -days 1000 -key mtls_setup/client-ca.key -out mtls_setup/client-ca.crt \
    -subj "/C=MA/ST=Tarfaya/L=Tarfaya/O=Fennec/OU=Aviator/CN=Client CA"

# Generate a certificate signing request (client CN is localhost which is used by smokescreen as the service name by default)
openssl req -newkey rsa:2048 -nodes -keyout mtls_setup/server.key -out mtls_setup/server.req \
    -subj "/C=AQ/ST=Petrel Island/L=Dumont-d'Urville/O=Chionis/OU=Publishing house/CN=server req"
openssl req -newkey rsa:2048 -nodes -keyout mtls_setup/client.key -out mtls_setup/client.req \
    -subj "/C=MA/ST=Tarfaya/L=Tarfaya/O=Addax/OU=Writer/CN=localhost"

# Have the CA sign the certificate requests and output the certificates.
echo "authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
" > mtls_setup/localhost.ext

openssl x509 -req -in mtls_setup/server.req -days 1000 -CA mtls_setup/server-ca.crt -CAkey mtls_setup/server-ca.key -set_serial 01 -out mtls_setup/server.crt -extfile mtls_setup/localhost.ext

openssl x509 -req -in mtls_setup/client.req -days 1000 -CA mtls_setup/client-ca.crt -CAkey mtls_setup/client-ca.key -set_serial 01 -out mtls_setup/client.crt
```

##### Configurations

```yaml
# config.yaml
---
tls:
  cert_file: "mtls_setup/server.crt"
  key_file: "mtls_setup/server.key"
  client_ca_files:
    - "mtls_setup/client-ca.crt"
```

```yaml
# acl.yaml
---
version: v1
services:
  - name: localhost
    project: github
    action: enforce
    allowed_domains:
      - api.github.com
default:
  name: default
  project: security
  action: enforce
  allowed_domains: []
```

#### Run

```bash
# Run smokescreen (in a different shell)
go run . --config-file config.yaml --egress-acl-file acl.yaml

# Curl
curl --proxytunnel -x https://localhost:4750 --proxy-cacert mtls_setup/server-ca.crt --proxy-cert mtls_setup/client.crt --proxy-key mtls_setup/client.key https://api.github.com/zen
# Curl with HTTPS_PROXY
HTTPS_PROXY=https://localhost:4750 curl --proxy-cacert mtls_setup/server-ca.crt --proxy-cert mtls_setup/client.crt --proxy-key mtls_setup/client.key https://api.github.com/zen
```

### MITM (Man in the middle) Proxy

#### Set-up

```yaml
# config.yaml
---
allow_missing_role: true  # skip mTLS client validation (use default ACL)
# Re-using goproxy library CA and key
mitm_ca_cert_file: "vendor/github.com/stripe/goproxy/ca.pem"
mitm_ca_key_file: "vendor/github.com/stripe/goproxy/key.pem"
```

```yaml
# acl.yaml
---
version: v1
services: []
default:
  name: default
  project: security
  action: enforce
  allowed_domains:
    - wttr.in
  mitm_domains:
  - domain: wttr.in
    add_headers:
      Accept-Language: el
    detailed_http_logs: true
    detailed_http_logs_full_headers:
      - User-Agent
```

#### Run

```bash
# Run smokescreen (in a different shell)
go run . --config-file config.yaml --egress-acl-file acl.yaml

# Curl (weather should be in Greek since we set the Accept-Language header)
curl --proxytunnel -x localhost:4750 --cacert vendor/github.com/stripe/goproxy/ca.pem https://wttr.in
# Curl with HTTPS_PROXY
HTTPS_PROXY=localhost:4750 curl --cacert vendor/github.com/stripe/goproxy/ca.pem https://wttr.in
```

### MITM (Man in the middle) Proxy over TLS

#### Set-up

Please generate the certificates from the TLS Generate certificates section.

```yaml
# config.yaml
---
tls:
  cert_file: "mtls_setup/server.crt"
  key_file: "mtls_setup/server.key"
  client_ca_files:
    - "mtls_setup/client-ca.crt"
# Re-using goproxy library CA and key
mitm_ca_cert_file: "vendor/github.com/stripe/goproxy/ca.pem"
mitm_ca_key_file: "vendor/github.com/stripe/goproxy/key.pem"
```

```yaml
# acl.yaml
---
version: v1
services:
  - name: localhost
    project: github
    action: enforce
    allowed_domains:
      - wttr.in
    mitm_domains:
      - domain: wttr.in
        add_headers:
          Accept-Language: el
        detailed_http_logs: true
        detailed_http_logs_full_headers:
          - User-Agent
default:
  name: default
  project: security
  action: enforce
  allowed_domains: []
```

#### Run

```bash
# Run smokescreen (in a different shell)
go run . --config-file config.yaml --egress-acl-file acl.yaml

# Curl (weather should be in Greek since we set the Accept-Language header)
curl --proxytunnel -x https://localhost:4750 --cacert vendor/github.com/stripe/goproxy/ca.pem --proxy-cacert mtls_setup/server-ca.crt --proxy-cert mtls_setup/client.crt --proxy-key mtls_setup/client.key https://wttr.in
# Curl with HTTPS_PROXY
HTTPS_PROXY=https://localhost:4750 curl --cacert vendor/github.com/stripe/goproxy/ca.pem --proxy-cacert mtls_setup/server-ca.crt --proxy-cert mtls_setup/client.crt --proxy-key mtls_setup/client.key https://wttr.in
```
