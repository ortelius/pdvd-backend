FROM cgr.dev/chainguard/go@sha256:aa48f5fe332cd6ac1a3dd5b616b002dbd54f292c93a077e768d7dbfbf9173fd2 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:ce2066b540536a53708fbb8e83c76add5fc1710cb4a923ac7cb466f91b2d911e

WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV MS_PORT=8080

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]
