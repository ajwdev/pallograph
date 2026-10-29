# Build with Nix, ship only the Nix store closure on scratch. Pattern from
# https://mitchellh.com/writing/nix-with-dockerfiles
FROM nixos/nix:2.35.4 AS builder

COPY . /tmp/build
WORKDIR /tmp/build

RUN nix \
    --extra-experimental-features "nix-command flakes" \
    --option filter-syscalls false \
    build .#container

# The closure is every store path the result needs at runtime, and nothing
# else. The binary is static, so this is mostly busybox and CA certs.
RUN mkdir /tmp/nix-store-closure
RUN cp -R $(nix-store -qR result/) /tmp/nix-store-closure

FROM scratch

COPY --from=builder /tmp/nix-store-closure /nix/store
COPY --from=builder /tmp/build/result /

# busybox in /bin provides the sh that shell datasources run.
ENV PATH=/bin
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
ENV HOME=/home/nonroot
WORKDIR /home/nonroot
USER 65532:65532

ENTRYPOINT ["/bin/pallograph"]
