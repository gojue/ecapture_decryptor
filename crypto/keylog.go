// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

package crypto

import (
	"bufio"
	"encoding/hex"
	"io"
	"strings"
)

// KeyLogStore stores TLS secrets from NSS key log format
type KeyLogStore struct {
	// Map from client random (hex) to secrets
	secrets map[string]*TLSSecrets
}

/*
https://github.com/cloudflare/ngtcp2/blob/e4d0b67e78c0cedc32f1c6e5c48e75c4d4282ff7/examples/keylog.cc#L47

client_early_traffic_secret: "QUIC_CLIENT_EARLY_TRAFFIC_SECRET",
client_handshake_traffic_secret: "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET",
server_handshake_traffic_secret: "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET",
client_traffic_secret_0: "QUIC_CLIENT_TRAFFIC_SECRET_0",
server_traffic_secret_0: "QUIC_SERVER_TRAFFIC_SECRET_0",
*/

type TLSSecrets struct {
	ClientTrafficSecret          []byte
	ServerTrafficSecret          []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	MasterSecret                 []byte // For TLS 1.2 and earlier
	ClientEarlyTrafficSecret     []byte // For 0-RTT
	ExporterSecret               []byte // Exporter secret
}

func NewKeyLogStore(f io.Reader) (*KeyLogStore, error) {
	kl := &KeyLogStore{
		secrets: make(map[string]*TLSSecrets),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}

		label := fields[0]
		clientRandom := fields[1]
		secretHex := fields[2]

		secret, err := hex.DecodeString(secretHex)
		if err != nil {
			continue
		}

		if kl.secrets[clientRandom] == nil {
			kl.secrets[clientRandom] = &TLSSecrets{}
		}

		switch label {
		case "CLIENT_TRAFFIC_SECRET_0":
			kl.secrets[clientRandom].ClientTrafficSecret = secret
		case "SERVER_TRAFFIC_SECRET_0":
			kl.secrets[clientRandom].ServerTrafficSecret = secret
		case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
			kl.secrets[clientRandom].ClientHandshakeTrafficSecret = secret
		case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
			kl.secrets[clientRandom].ServerHandshakeTrafficSecret = secret
		case "CLIENT_RANDOM":
			kl.secrets[clientRandom].MasterSecret = secret
		case "CLIENT_EARLY_TRAFFIC_SECRET":
			kl.secrets[clientRandom].ClientEarlyTrafficSecret = secret
		case "EXPORTER_SECRET":
			kl.secrets[clientRandom].ExporterSecret = secret

		// QUIC specific labels
		case "QUIC_CLIENT_EARLY_TRAFFIC_SECRET":
			kl.secrets[clientRandom].ClientEarlyTrafficSecret = secret
		case "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET":
			kl.secrets[clientRandom].ClientHandshakeTrafficSecret = secret
		case "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET":
			kl.secrets[clientRandom].ServerHandshakeTrafficSecret = secret
		case "QUIC_CLIENT_TRAFFIC_SECRET_0":
			kl.secrets[clientRandom].ClientTrafficSecret = secret
		case "QUIC_SERVER_TRAFFIC_SECRET_0":
			kl.secrets[clientRandom].ServerTrafficSecret = secret
		}
	}

	return kl, scanner.Err()
}

func (kl *KeyLogStore) GetSecrets(clientRandom []byte) *TLSSecrets {
	key := hex.EncodeToString(clientRandom)
	return kl.secrets[key]
}
