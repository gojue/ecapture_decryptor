// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// factory.go - Decryptor factory for library mode
package ecapture_decryptor

import (
	"io"
	"log"
	"os"
	"sync"

	"github.com/gojue/ecapture_decryptor/crypto"
	"github.com/gojue/ecapture_decryptor/transport"
	"github.com/gojue/ecapture_decryptor/types"
)

// DecryptorCreator 解密器创建函数类型
type DecryptorCreator func(key types.ConnectionKey, f *DecryptorFactory) types.Decryptor

// decryptorRegistry 解密器注册表
var (
	decryptorRegistry   = make(map[string]DecryptorCreator)
	decryptorRegistryMu sync.RWMutex
)

// RegisterDecryptor 注册解密器创建函数
func RegisterDecryptor(proto string, creator DecryptorCreator) {
	decryptorRegistryMu.Lock()
	defer decryptorRegistryMu.Unlock()
	decryptorRegistry[proto] = creator
}

// DecryptorFactory 解密器工厂
type DecryptorFactory struct {
	keyLog     *crypto.KeyLogStore
	stdout     io.Writer
	stderr     io.Writer
	logger     *log.Logger
	packetChan chan *types.DecryptedPacket // 解密包输出通道
}

// NewDecryptorFactory 创建解密器工厂
func NewDecryptorFactory(keyLog *crypto.KeyLogStore, logger *log.Logger, packetChan chan *types.DecryptedPacket) *DecryptorFactory {
	return &DecryptorFactory{
		keyLog:     keyLog,
		stdout:     os.Stdout,
		stderr:     os.Stdout,
		logger:     logger,
		packetChan: packetChan,
	}
}

// Create 根据连接键创建对应的解密器
func (f *DecryptorFactory) Create(key types.ConnectionKey) types.Decryptor {
	decryptorRegistryMu.RLock()
	creator, ok := decryptorRegistry[key.Proto]
	decryptorRegistryMu.RUnlock()

	if !ok {
		f.logger.Printf("Unsupported protocol: %s", key.Proto)
		return nil
	}

	return creator(key, f)
}

// GetKeyLog returns the key log store
func (f *DecryptorFactory) GetKeyLog() *crypto.KeyLogStore {
	return f.keyLog
}

// GetLogger returns the logger
func (f *DecryptorFactory) GetLogger() *log.Logger {
	return f.logger
}

// GetPacketChan returns the packet output channel
func (f *DecryptorFactory) GetPacketChan() chan *types.DecryptedPacket {
	return f.packetChan
}

// GetStdout returns stdout writer
func (f *DecryptorFactory) GetStdout() io.Writer {
	return f.stdout
}

// GetStderr returns stderr writer
func (f *DecryptorFactory) GetStderr() io.Writer {
	return f.stderr
}

// SetOutput sets the output writers
func (f *DecryptorFactory) SetOutput(stdout, stderr io.Writer) {
	f.stdout = stdout
	f.stderr = stderr
}

func init() {
	// Register TCP/TLS decryptor
	RegisterDecryptor("tcp", func(key types.ConnectionKey, f *DecryptorFactory) types.Decryptor {
		return transport.NewTLSDecryptorLibrary(
			key,
			f.keyLog,
			f.stdout,
			f.stderr,
			f.logger,
			f.packetChan,
		)
	})

	// Register UDP/QUIC decryptor
	RegisterDecryptor("udp", func(key types.ConnectionKey, f *DecryptorFactory) types.Decryptor {
		return transport.NewQUICDecryptor(
			key,
			f.keyLog,
			f.logger,
			f.stdout,
			f.packetChan,
		)
	})
}
