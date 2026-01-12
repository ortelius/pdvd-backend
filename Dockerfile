FROM cgr.dev/chainguard/go@sha256:4df33e10008e496f71d3ae659298570e92066f33afa6d71ba5f0acbd354b9173 AS builder

WORKDIR /app
COPY . /app

RUN go mod tidy; \
    go build -o main .

FROM cgr.dev/chainguard/glibc-dynamic@sha256:dc8241ac0644475f183a4e090c3ac1481fd8536dc7acd0b1d31325af15263998

WORKDIR /app

COPY --from=builder /app/main .

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV MS_PORT=8080

EXPOSE 8080

ENTRYPOINT [ "/app/main" ]
