FROM golang AS builder
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go install

FROM scratch
COPY --from=builder /go/bin/homedirs /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY static /static
USER 999
ENV GIN_MODE=release
ENTRYPOINT ["/homedirs"]
