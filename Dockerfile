FROM cgr.dev/chainguard/go@sha256:642155ee6bc2bd549cd1b1360def4af95e67b55b7044f95216ac43c6f7ef25ab AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:470109ff06cafa56ff55bf1d51e6e2f2f5bdcf2d56692d96b515a193ac3ee5b2
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV MS_PORT=8080

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]

