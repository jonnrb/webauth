from quay.io/jonnrb/go as build
add go.* ./
run go mod download
add . ./
run CGO_ENABLED=0 go get ./cmd/webauth

from gcr.io/distroless/static
copy --from=build /go/bin/webauth /
entrypoint ["/webauth"]
