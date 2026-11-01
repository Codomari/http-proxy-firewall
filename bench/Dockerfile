ARG GO_IMAGE=golang:1.27-alpine
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY bench ./bench
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /benchmark ./bench

FROM scratch
COPY --from=build /benchmark /benchmark
ENTRYPOINT ["/benchmark"]
