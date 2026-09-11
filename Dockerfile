FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev cmake clang make perl ca-certificates
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked -j 4 && \
    strip target/release/smtp-proxy

FROM scratch
COPY --from=build /src/target/release/smtp-proxy /app/bin/smtp-proxy
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 3000/tcp
ENTRYPOINT ["/app/bin/smtp-proxy"]
