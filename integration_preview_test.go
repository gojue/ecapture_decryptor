package ecapture_decryptor

import (
	"strings"
	"testing"

	"github.com/gojue/ecapture_decryptor/types"
)

func logDecryptedPreview(t *testing.T, packet *types.DecryptedPacket) {
	t.Helper()
	preview := packet.Data
	if len(preview) > 100 {
		preview = preview[:100]
	}
	lines := strings.Split(string(preview), "\n")
	for i, line := range lines {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "cookie", "set-cookie", "authorization", "proxy-authorization":
			lines[i] = name + ": [redacted]"
		}
	}
	t.Logf("%s %s: %d bytes, preview of first %d bytes: %q",
		packet.Protocol, packet.Direction, len(packet.Data), len(preview), strings.Join(lines, "\n"))
}
