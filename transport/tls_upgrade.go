// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
// See LICENSE for the applicable license.

package transport

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	maxTLSUpgradeBuffer = 64 << 10
	maxTLSUpgradeBytes  = 1 << 20
	maxTLSUpgradeSteps  = 4096
)

var (
	errTLSUpgrade      = errors.New("invalid TLS upgrade negotiation")
	errTLSUpgradeLimit = errors.New("TLS upgrade negotiation limit exceeded")
)

type tlsUpgradeChunk struct {
	data   []byte
	client bool
	tls    bool
}

// tlsUpgrade recognizes one explicitly selected negotiation, not arbitrary TLS
// record prefixes. Its caller serializes Feed/Close/Upgraded. Returned chunks own
// their bytes and preserve each direction's exact byte order. A refusal or an
// unsupported plaintext operation permanently selects plaintext passthrough.
type tlsUpgrade struct {
	protocol                string
	buf                     [2][]byte
	scan                    [2]int
	phase, total, steps     int
	replyCode, messageID    int
	command, tag            string
	upgraded, plain, closed bool
	err                     error
}

func newTLSUpgrade(protocol string) (*tlsUpgrade, error) {
	switch protocol {
	case "smtp", "imap", "pop3", "ldap", "postgres", "mysql", "connect":
		return &tlsUpgrade{protocol: protocol}, nil
	default:
		return nil, errTLSUpgrade
	}
}

func (u *tlsUpgrade) Upgraded() bool { return u.upgraded }
func (u *tlsUpgrade) Finished() bool { return u.upgraded || u.plain }

func upgradeChunk(out *[]tlsUpgradeChunk, data []byte, client, tls bool) {
	if len(data) == 0 {
		return
	}
	if n := len(*out); n > 0 && (*out)[n-1].client == client && (*out)[n-1].tls == tls {
		(*out)[n-1].data = append((*out)[n-1].data, data...)
		return
	}
	*out = append(*out, tlsUpgradeChunk{bytes.Clone(data), client, tls})
}

func (u *tlsUpgrade) take(out *[]tlsUpgradeChunk, side, n int) {
	upgradeChunk(out, u.buf[side][:n], side == 0, false)
	u.buf[side] = u.buf[side][n:]
	u.scan[side] = 0
	if len(u.buf[side]) == 0 {
		u.buf[side] = nil
	}
}

func (u *tlsUpgrade) Feed(data []byte, client bool) (out []tlsUpgradeChunk, err error) {
	if u.err != nil {
		return nil, u.err
	}
	if u.closed {
		return nil, io.ErrClosedPipe
	}
	defer func() {
		if err != nil {
			u.err = err
			u.buf = [2][]byte{}
			u.scan = [2]int{}
		}
	}()
	side := 1
	if client {
		side = 0
	}
	for len(data) > 0 {
		if u.upgraded || u.plain {
			upgradeChunk(&out, data, client, u.upgraded)
			break
		}
		n := min(len(data), maxTLSUpgradeBuffer-len(u.buf[side]))
		if n == 0 || n > maxTLSUpgradeBytes-u.total {
			return out, errTLSUpgradeLimit
		}
		u.buf[side] = append(u.buf[side], data[:n]...)
		u.total += n
		data = data[n:]
		for !u.upgraded && !u.plain {
			var advanced bool
			advanced, err = u.step(&out)
			if err != nil {
				return out, err
			}
			if !advanced {
				break
			}
			u.steps++
			if u.steps > maxTLSUpgradeSteps {
				return out, errTLSUpgradeLimit
			}
		}
		if u.upgraded || u.plain {
			for i := range u.buf {
				upgradeChunk(&out, u.buf[i], i == 0, u.upgraded)
				u.buf[i] = nil
				u.scan[i] = 0
			}
		}
	}
	return out, nil
}

func (u *tlsUpgrade) Close() error {
	if !u.closed {
		u.closed = true
		if u.err == nil && !u.upgraded && !u.plain && u.total != 0 {
			u.err = io.ErrUnexpectedEOF
		}
		u.buf = [2][]byte{}
		u.scan = [2]int{}
	}
	return u.err
}

func (u *tlsUpgrade) step(out *[]tlsUpgradeChunk) (bool, error) {
	switch u.protocol {
	case "smtp":
		return u.smtp(out)
	case "imap":
		return u.imap(out)
	case "pop3":
		return u.pop3(out)
	case "ldap":
		return u.ldap(out)
	case "postgres":
		return u.postgres(out)
	case "mysql":
		return u.mysql(out)
	default:
		return u.connect(out)
	}
}

func (u *tlsUpgrade) line(side int) ([]byte, int, error) {
	b := u.buf[side]
	i := bytes.IndexByte(b[u.scan[side]:], '\n')
	if i < 0 {
		u.scan[side] = len(b)
		return nil, 0, nil
	}
	i += u.scan[side]
	if i == 0 || b[i-1] != '\r' {
		return nil, 0, errTLSUpgrade
	}
	for _, c := range b[:i-1] {
		if c < 32 && c != '\t' || c == 127 {
			return nil, 0, errTLSUpgrade
		}
	}
	return b[:i-1], i + 1, nil
}

// SMTP covers the greeting and non-body pre-auth commands. DATA/AUTH/BDAT and
// other commands select plaintext permanently, so message content cannot be
// mistaken for a later STARTTLS command (RFC 3207 / RFC 5321).
func (u *tlsUpgrade) smtp(out *[]tlsUpgradeChunk) (bool, error) {
	side := 1
	if u.phase == 1 {
		side = 0
	}
	line, n, err := u.line(side)
	if err != nil || n == 0 {
		return false, err
	}
	if side == 0 {
		fields := strings.Fields(string(line))
		if len(fields) == 0 {
			return false, errTLSUpgrade
		}
		u.command = strings.ToUpper(fields[0])
		switch u.command {
		case "STARTTLS", "RSET":
			if len(fields) != 1 {
				return false, errTLSUpgrade
			}
		case "EHLO", "HELO":
			if len(fields) != 2 {
				return false, errTLSUpgrade
			}
		case "NOOP":
		default:
			u.plain = true
		}
		u.phase = 2
	} else {
		if len(line) < 3 || line[0] < '2' || line[0] > '5' || line[1] < '0' || line[1] > '9' || line[2] < '0' || line[2] > '9' || len(line) > 3 && line[3] != ' ' && line[3] != '-' {
			return false, errTLSUpgrade
		}
		code := int(line[0]-'0')*100 + int(line[1]-'0')*10 + int(line[2]-'0')
		if u.replyCode != 0 && u.replyCode != code {
			return false, errTLSUpgrade
		}
		if len(line) > 3 && line[3] == '-' {
			u.replyCode = code
		} else {
			u.replyCode = 0
			if u.phase == 0 {
				u.plain = code != 220
			} else if u.command == "STARTTLS" {
				u.upgraded, u.plain = code == 220, code != 220
			} else if code >= 300 && code < 400 {
				u.plain = true // Do not interpret an unexpected data continuation.
			}
			u.phase = 1
		}
	}
	u.take(out, side, n)
	return true, nil
}

func upgradeIMAPTag(tag string) bool {
	if len(tag) == 0 || len(tag) > 128 {
		return false
	}
	for _, c := range []byte(tag) {
		if c <= 32 || c >= 127 || strings.ContainsRune("(){%*\"\\]+", rune(c)) {
			return false
		}
	}
	return true
}

// IMAP only crosses a matching tagged OK, never an untagged capability or OK
// line. Literal-bearing/authenticated commands stop detection (RFC 3501 6.2.1).
func (u *tlsUpgrade) imap(out *[]tlsUpgradeChunk) (bool, error) {
	side := 1
	if u.phase == 1 {
		side = 0
	}
	line, n, err := u.line(side)
	if err != nil || n == 0 {
		return false, err
	}
	f := strings.Fields(string(line))
	if len(f) < 2 {
		return false, errTLSUpgrade
	}
	if side == 0 {
		if !upgradeIMAPTag(f[0]) {
			return false, errTLSUpgrade
		}
		u.tag, u.command = f[0], strings.ToUpper(f[1])
		switch u.command {
		case "STARTTLS", "CAPABILITY", "NOOP":
			if len(f) != 2 {
				return false, errTLSUpgrade
			}
		default:
			u.plain = true
		}
		u.phase = 2
	} else if u.phase == 0 {
		if f[0] != "*" {
			return false, errTLSUpgrade
		}
		switch strings.ToUpper(f[1]) {
		case "OK":
			u.phase = 1
		case "PREAUTH", "BYE":
			u.plain = true
		default:
			return false, errTLSUpgrade
		}
	} else if f[0] == "*" {
		switch strings.ToUpper(f[1]) {
		case "CAPABILITY", "OK", "NO", "BAD":
		case "BYE":
			u.plain = true
		default:
			u.plain = true // Do not parse literals or mailbox data as line replies.
		}
	} else {
		if f[0] != u.tag {
			return false, errTLSUpgrade
		}
		status := strings.ToUpper(f[1])
		if status != "OK" && status != "NO" && status != "BAD" {
			return false, errTLSUpgrade
		}
		if u.command == "STARTTLS" {
			u.upgraded, u.plain = status == "OK", status != "OK"
		}
		u.phase = 1
	}
	u.take(out, side, n)
	return true, nil
}

func upgradePOPStatus(line []byte) (bool, error) {
	s := string(line)
	if s == "+OK" || strings.HasPrefix(s, "+OK ") {
		return true, nil
	}
	if s == "-ERR" || strings.HasPrefix(s, "-ERR ") {
		return false, nil
	}
	return false, errTLSUpgrade
}

// POP3 CAPA has a dot-terminated reply. STLS accepts only the single +OK reply
// boundary, not an apparent +OK inside capability or message data (RFC 2595).
func (u *tlsUpgrade) pop3(out *[]tlsUpgradeChunk) (bool, error) {
	side := 1
	if u.phase == 1 {
		side = 0
	}
	line, n, err := u.line(side)
	if err != nil || n == 0 {
		return false, err
	}
	if side == 0 {
		f := strings.Fields(string(line))
		if len(f) == 0 {
			return false, errTLSUpgrade
		}
		u.command = strings.ToUpper(f[0])
		switch u.command {
		case "STLS", "CAPA", "NOOP":
			if len(f) != 1 {
				return false, errTLSUpgrade
			}
		default:
			u.plain = true
		}
		u.phase = 2
	} else if u.phase == 3 {
		if bytes.Equal(line, []byte(".")) {
			u.phase = 1
		}
	} else {
		ok, err := upgradePOPStatus(line)
		if err != nil {
			return false, err
		}
		if u.phase == 0 {
			u.plain = !ok
		} else if u.command == "STLS" {
			u.upgraded, u.plain = ok, !ok
		}
		u.phase = 1
		if u.command == "CAPA" && ok {
			u.phase = 3
		}
	}
	u.take(out, side, n)
	return true, nil
}

// upgradeBER accepts definite-length LDAP BER only, with a bounded envelope.
func upgradeBER(data []byte) (tag byte, value []byte, size int, err error) {
	if len(data) < 2 {
		return 0, nil, 0, nil
	}
	tag, head, n := data[0], 2, int(data[1])
	if tag&31 == 31 {
		return 0, nil, 0, errTLSUpgrade
	}
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 4 {
			return 0, nil, 0, errTLSUpgrade
		}
		if len(data) < 2+count {
			return 0, nil, 0, nil
		}
		head, n = 2+count, 0
		for _, v := range data[2:head] {
			if n > maxTLSUpgradeBuffer/256 {
				return 0, nil, 0, errTLSUpgradeLimit
			}
			n = n*256 + int(v)
		}
	}
	if n > maxTLSUpgradeBuffer-head {
		return 0, nil, 0, errTLSUpgradeLimit
	}
	if len(data) < head+n {
		return tag, nil, 0, nil
	}
	return tag, data[head : head+n], head + n, nil
}

func upgradeLDAPField(data *[]byte, want byte) ([]byte, error) {
	tag, value, n, err := upgradeBER(*data)
	if err != nil || n == 0 || tag != want {
		return nil, errTLSUpgrade
	}
	*data = (*data)[n:]
	return value, nil
}

func upgradeLDAPInt(data []byte) (int, error) {
	if len(data) == 0 || len(data) > 4 || data[0]&128 != 0 {
		return 0, errTLSUpgrade
	}
	n := 0
	for _, v := range data {
		n = n*256 + int(v)
	}
	return n, nil
}

func (u *tlsUpgrade) ldap(out *[]tlsUpgradeChunk) (bool, error) {
	side := u.phase // First client ExtendedRequest, then matching server result.
	tag, body, n, err := upgradeBER(u.buf[side])
	if err != nil || n == 0 {
		return false, err
	}
	if tag != 0x30 {
		return false, errTLSUpgrade
	}
	idBytes, err := upgradeLDAPField(&body, 2)
	if err != nil {
		return false, err
	}
	id, err := upgradeLDAPInt(idBytes)
	if err != nil || id == 0 {
		return false, errTLSUpgrade
	}
	op, operation, size, err := upgradeBER(body)
	if err != nil || size == 0 {
		return false, errTLSUpgrade
	}
	body = body[size:]
	if len(body) > 0 {
		if _, err := upgradeLDAPField(&body, 0xa0); err != nil || len(body) != 0 {
			return false, errTLSUpgrade
		}
	}
	const oid = "1.3.6.1.4.1.1466.20037"
	if side == 0 {
		if op != 0x77 {
			u.plain = true
		} else {
			name, err := upgradeLDAPField(&operation, 0x80)
			if err != nil {
				return false, err
			}
			if string(name) != oid {
				u.plain = true
			} else if len(operation) != 0 {
				return false, errTLSUpgrade // StartTLS has no requestValue.
			}
		}
		u.messageID, u.phase = id, 1
	} else {
		if op != 0x78 || id != u.messageID {
			return false, errTLSUpgrade
		}
		codeBytes, err := upgradeLDAPField(&operation, 0x0a)
		if err != nil {
			return false, err
		}
		code, err := upgradeLDAPInt(codeBytes)
		if err != nil {
			return false, err
		}
		for i := 0; i < 2; i++ { // matchedDN and diagnosticMessage, never exposed in errors.
			if _, err := upgradeLDAPField(&operation, 4); err != nil {
				return false, err
			}
		}
		if len(operation) > 0 && operation[0] == 0xa3 {
			if _, err := upgradeLDAPField(&operation, 0xa3); err != nil {
				return false, err
			}
		}
		if len(operation) > 0 {
			name, err := upgradeLDAPField(&operation, 0x8a)
			if err != nil || string(name) != oid || len(operation) != 0 {
				return false, errTLSUpgrade // responseValue is prohibited.
			}
		}
		u.upgraded, u.plain = code == 0, code != 0
	}
	u.take(out, side, n)
	return true, nil
}

func (u *tlsUpgrade) postgres(out *[]tlsUpgradeChunk) (bool, error) {
	if u.phase == 0 {
		b := u.buf[0]
		if len(b) < 4 {
			return false, nil
		}
		n := int64(binary.BigEndian.Uint32(b))
		if n < 8 {
			return false, errTLSUpgrade
		}
		if n > maxTLSUpgradeBuffer {
			return false, errTLSUpgradeLimit
		}
		if int64(len(b)) < n {
			return false, nil
		}
		u.plain = n != 8 || binary.BigEndian.Uint32(b[4:8]) != 80877103
		u.take(out, 0, int(n))
		u.phase = 1
	} else {
		if len(u.buf[1]) == 0 {
			return false, nil
		}
		switch u.buf[1][0] {
		case 'S':
			u.upgraded = true
		case 'N', 'E':
			u.plain = true
		default:
			return false, errTLSUpgrade
		}
		u.take(out, 1, 1)
	}
	return true, nil
}

func (u *tlsUpgrade) mysql(out *[]tlsUpgradeChunk) (bool, error) {
	side := 1 - u.phase
	b := u.buf[side]
	if len(b) < 4 {
		return false, nil
	}
	n := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if n > maxTLSUpgradeBuffer-4 {
		return false, errTLSUpgradeLimit
	}
	if n == 0 || int(b[3]) != u.phase {
		return false, errTLSUpgrade
	}
	if len(b) < n+4 {
		return false, nil
	}
	body := b[4 : n+4]
	const required = 0x0200 | 0x0800 // CLIENT_PROTOCOL_41 | CLIENT_SSL
	if u.phase == 0 {
		if body[0] == 0xff || body[0] != 10 {
			u.plain = true
		} else {
			end := bytes.IndexByte(body[1:], 0)
			if end < 0 || len(body) < end+17 || body[end+14] != 0 {
				return false, errTLSUpgrade
			}
			caps := binary.LittleEndian.Uint16(body[end+15 : end+17])
			u.plain = caps&required != required
			if !u.plain && len(body) < end+33 {
				return false, errTLSUpgrade
			}
		}
		u.phase = 1
	} else {
		if len(body) != 32 || binary.LittleEndian.Uint32(body)&required != required {
			u.plain = true
		} else {
			for _, v := range body[9:] {
				if v != 0 {
					return false, errTLSUpgrade
				}
			}
			u.upgraded = true // MySQL has no plaintext SSLRequest acknowledgement.
		}
	}
	u.take(out, side, n+4)
	return true, nil
}

func (u *tlsUpgrade) connect(out *[]tlsUpgradeChunk) (bool, error) {
	side := u.phase
	b := u.buf[side]
	n := bytes.Index(b[u.scan[side]:], []byte("\r\n\r\n"))
	if n < 0 {
		u.scan[side] = max(0, len(b)-3)
		return false, nil
	}
	n += u.scan[side] + 4
	if side == 0 {
		r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b[:n])))
		if err != nil || r.ProtoMajor != 1 || r.ProtoMinor > 1 {
			return false, errTLSUpgrade
		}
		if r.Method != "CONNECT" {
			u.plain = true
		} else {
			host, port, err := net.SplitHostPort(r.RequestURI)
			p, portErr := strconv.Atoi(port)
			if err != nil || host == "" || strings.ContainsAny(host, "/?#@\\[]") || strings.Contains(host, ":") && net.ParseIP(host) == nil || portErr != nil || p < 1 || p > 65535 || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
				return false, errTLSUpgrade
			}
			for _, c := range []byte(port) {
				if c < '0' || c > '9' {
					return false, errTLSUpgrade
				}
			}
		}
		u.phase = 1
	} else {
		reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(b[:n])))
		line, err := reader.ReadLine()
		if err != nil {
			return false, errTLSUpgrade
		}
		f := strings.SplitN(line, " ", 3)
		if len(f) < 2 || f[0] != "HTTP/1.0" && f[0] != "HTTP/1.1" || len(f[1]) != 3 {
			return false, errTLSUpgrade
		}
		code, err := strconv.Atoi(f[1])
		if err != nil || code < 100 || code > 599 {
			return false, errTLSUpgrade
		}
		if _, err := reader.ReadMIMEHeader(); err != nil {
			return false, errTLSUpgrade
		}
		// RFC 9110: successful CONNECT has no body; ignore CL/TE and hand off
		// precisely after the header block, including non-200 2xx responses.
		if code >= 200 && code < 300 {
			u.upgraded = true
		} else if code == 101 || code >= 300 {
			u.plain = true
		}
	}
	u.take(out, side, n)
	return true, nil
}
