// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// tls_wrapper.go - TLS 解密器包装
package transport

import (
	"io"
	"log"
	"time"

	"github.com/cfc4n/ecapture_decryptor/crypto"
	"github.com/cfc4n/ecapture_decryptor/types"
)

// TLSDecryptorWrapper wraps TLSDecryptor to implement Decryptor interface
type TLSDecryptorWrapper struct {
	*TLSDecryptor
}

// NewTLSDecryptorWrapper creates a new TLS decryptor wrapper
func NewTLSDecryptorWrapper(ci types.ConnectionKey, keyLog *crypto.KeyLogStore, clientOut, serverOut io.Writer, logger *log.Logger, packetChan chan *types.DecryptedPacket) types.Decryptor {
	return &TLSDecryptorWrapper{
		TLSDecryptor: NewTLSDecryptor(ci, keyLog, clientOut, serverOut, logger, packetChan),
	}
}

// NewTLSDecryptorLibrary creates a TLS decryptor for library mode
func NewTLSDecryptorLibrary(ci types.ConnectionKey, keyLog *crypto.KeyLogStore, clientOut, serverOut io.Writer, logger *log.Logger, packetChan chan *types.DecryptedPacket) types.Decryptor {
	return NewTLSDecryptorWrapper(ci, keyLog, clientOut, serverOut, logger, packetChan)
}

// GetAddr returns the connection address
func (w *TLSDecryptorWrapper) GetAddr() types.ConnectionKey {
	return w.ConnectionInfo
}

// Decrypt starts the decryption process
func (w *TLSDecryptorWrapper) Decrypt() error {
	return w.TLSDecryptor.Decrypt()
}

// FeedClient feeds client data to the decryptor
func (w *TLSDecryptorWrapper) FeedClient(data []byte) error {
	return w.TLSDecryptor.FeedClient(data)
}

// FeedServer feeds server data to the decryptor
func (w *TLSDecryptorWrapper) FeedServer(data []byte) error {
	return w.TLSDecryptor.FeedServer(data)
}

// SetPacketTime sets the packet timestamp
func (w *TLSDecryptorWrapper) SetPacketTime(t time.Time) {
	w.TLSDecryptor.SetPacketTime(t)
}

// CloseClient closes the client side
func (w *TLSDecryptorWrapper) CloseClient() error {
	return w.TLSDecryptor.CloseClient()
}

// CloseServer closes the server side
func (w *TLSDecryptorWrapper) CloseServer() error {
	return w.TLSDecryptor.CloseServer()
}

// Close closes the decryptor
func (w *TLSDecryptorWrapper) Close() error {
	return w.TLSDecryptor.Close()
}
