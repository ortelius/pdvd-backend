FROM cgr.dev/chainguard/go@sha256:c37ab722f014bacc0375b471341437fbe4c879c78e8c5153376674c637a83168 AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:32e4a9556c591d7a6bfcaf4712d102a943c921c3674a3d07673c8d7cd2e18456
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

