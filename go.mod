module github.com/gojue/ecapture_decryptor

go 1.26.0

require (
	github.com/google/gopacket v1.1.19
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
)

require (
	github.com/quic-go/qpack v0.6.0
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/google/gopacket v1.1.19 => github.com/cfc4n/gopacket v1.1.20
