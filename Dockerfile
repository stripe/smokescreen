# Release packaging context contains amd64/ and arm64/ from verified tarballs.
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG TARGETARCH
COPY --chmod=0555 ${TARGETARCH}/smokescreen /smokescreen
USER 65532:65532
EXPOSE 4750
ENTRYPOINT ["/smokescreen"]
CMD ["--listen-ip", "0.0.0.0", "--listen-port", "4750"]
