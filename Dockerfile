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
# --user resolves the name with getpwnam, which reads these two files. The
# Perl image was alpine and had them; a scratch image has nothing, so the
# flag would abort every start with "Cannot resolve username".
COPY --from=build /etc/passwd /etc/group /etc/
EXPOSE 3000/tcp
ENTRYPOINT ["/app/bin/smtp-proxy"]
