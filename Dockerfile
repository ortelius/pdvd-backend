FROM cgr.dev/chainguard/go@sha256:c07071b612886c9970bb4a632ec7a0da5c040f992e489fdbb072617832a246c1 AS builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /app
COPY . /app

RUN go mod tidy && \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:90a226a4a32aa8656cc40545ca58d8909ced8977494393e86937ba5a0fbb23c3
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

