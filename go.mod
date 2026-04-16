module github.com/tiiuae/nats-server/v2

go 1.25.0

toolchain go1.25.9

replace github.com/nats-io/nats.go => github.com/tiiuae/nats.go v0.0.0-20260416105712-bd2199d5cc10

require (
	github.com/antithesishq/antithesis-sdk-go v0.6.0-default-no-op
	github.com/google/go-tpm v0.9.8
	github.com/klauspost/compress v1.18.5
	github.com/nats-io/jwt/v2 v2.8.1
	github.com/nats-io/nats.go v1.50.0
	github.com/nats-io/nkeys v0.4.15
	github.com/nats-io/nuid v1.0.1
	github.com/pion/rtcp v1.2.15
	github.com/pion/rtp v1.8.21
	github.com/quic-go/quic-go v0.48.1
	golang.org/x/crypto v0.49.0
	golang.org/x/sys v0.42.0
	golang.org/x/time v0.15.0
)

require (
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
)

// We don't usually pin non-tagged commits but so far no release has
// been made that includes https://github.com/minio/highwayhash/pull/29.
// This will be updated if a new tag covers this in the future.
require github.com/minio/highwayhash v1.0.4-0.20251030100505-070ab1a87a76
