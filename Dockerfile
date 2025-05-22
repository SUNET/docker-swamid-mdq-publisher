FROM golang:1.22.2-bullseye AS build
WORKDIR /go/src/mdq-publisher
COPY build .

RUN go mod download
RUN go test -race ./...
RUN CGO_ENABLED=0 go build -o /go/bin/mdq-publisher

FROM gcr.io/distroless/static-debian12
COPY --from=build /go/bin/mdq-publisher /
EXPOSE 443
CMD ["/mdq-publisher"]
