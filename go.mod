module github.com/cfc4n/ecapture_decryptor

go 1.24.0

toolchain go1.24.3

require (
	github.com/google/gopacket v1.1.19
	golang.org/x/crypto v0.46.0
	golang.org/x/net v0.48.0
)

require (
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/google/gopacket v1.1.19 => github.com/cfc4n/gopacket v1.1.20
