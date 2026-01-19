FROM cgr.dev/chainguard/go@sha256:2f66097733a33e04af1b531a3aac6f9da80d13f6b4ea34f9d1dadc00fb609561 AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:4a9bf947d321c102a5105ab2a429dcf08edc5b6fb053dae52c4e231326e2cd1f
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

