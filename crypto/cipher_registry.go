// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// cipher_registry.go - 密码套件注册机制
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuiteConfig 密码套件配置
type CipherSuiteConfig struct {
	ID       uint16
	Name     string
	Version  TLSVersionType // TLS 1.2, TLS 1.3, or Both
	KeyLen   int
	MacLen   int // 0 for AEAD
	IVLen    int
	HashFunc func() hash.Hash
	IsAEAD   bool
	// AEADFactory 创建 AEAD 密码
	AEADFactory func(key []byte) (cipher.AEAD, error)
}

// TLSVersionType TLS 版本类型
type TLSVersionType int

const (
	TLSVersion12   TLSVersionType = 1
	TLSVersion13   TLSVersionType = 2
	TLSVersionBoth TLSVersionType = 3
)

// cipherSuiteRegistry 全局密码套件注册表
var (
	cipherSuiteRegistry   = make(map[uint16]*CipherSuiteConfig)
	cipherSuiteRegistryMu sync.RWMutex
)

// RegisterCipherSuite 注册一个密码套件
func RegisterCipherSuite(config *CipherSuiteConfig) {
	cipherSuiteRegistryMu.Lock()
	defer cipherSuiteRegistryMu.Unlock()
	cipherSuiteRegistry[config.ID] = config
}

// GetCipherSuite 获取密码套件配置
func GetCipherSuite(id uint16) (*CipherSuiteConfig, bool) {
	cipherSuiteRegistryMu.RLock()
	defer cipherSuiteRegistryMu.RUnlock()
	config, ok := cipherSuiteRegistry[id]
	return config, ok
}

// GetCipherSuiteName 获取密码套件名称
func GetCipherSuiteName(id uint16) string {
	if config, ok := GetCipherSuite(id); ok {
		return config.Name
	}
	return fmt.Sprintf("Unknown(0x%04x)", id)
}

// IsCipherSuiteSupported 检查密码套件是否支持
func IsCipherSuiteSupported(id uint16) bool {
	_, ok := GetCipherSuite(id)
	return ok
}

// CreateAEAD 根据密码套件创建 AEAD
func CreateAEAD(id uint16, key []byte) (cipher.AEAD, error) {
	config, ok := GetCipherSuite(id)
	if !ok {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", id)
	}
	if config.AEADFactory == nil {
		return nil, fmt.Errorf("cipher suite 0x%04x does not support AEAD", id)
	}
	return config.AEADFactory(key)
}

// AEAD 工厂函数
func newAESGCMCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newChaCha20Poly1305Cipher(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// TLS 版本名称映射
var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// GetTLSVersionName 获取 TLS 版本名称
func GetTLSVersionName(version uint16) string {
	if name, ok := tlsVersionNames[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", version)
}

// init 注册所有内置密码套件
func init() {
	// TLS 1.3 密码套件
	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_AES_128_GCM_SHA256,
		Name:        "TLS_AES_128_GCM_SHA256",
		Version:     TLSVersion13,
		KeyLen:      16,
		MacLen:      0,
		IVLen:       12,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_AES_256_GCM_SHA384,
		Name:        "TLS_AES_256_GCM_SHA384",
		Version:     TLSVersion13,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       12,
		HashFunc:    sha512.New384,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_CHACHA20_POLY1305_SHA256,
		Name:        "TLS_CHACHA20_POLY1305_SHA256",
		Version:     TLSVersion13,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       12,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newChaCha20Poly1305Cipher,
	})

	// TLS 1.2 CBC 密码套件
	RegisterCipherSuite(&CipherSuiteConfig{
		ID:       tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		Name:     "TLS_RSA_WITH_AES_128_CBC_SHA",
		Version:  TLSVersion12,
		KeyLen:   16,
		MacLen:   20,
		IVLen:    16,
		HashFunc: sha256.New,
		IsAEAD:   false,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:       tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		Name:     "TLS_RSA_WITH_AES_256_CBC_SHA",
		Version:  TLSVersion12,
		KeyLen:   32,
		MacLen:   20,
		IVLen:    16,
		HashFunc: sha256.New,
		IsAEAD:   false,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:       tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		Name:     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		Version:  TLSVersion12,
		KeyLen:   16,
		MacLen:   20,
		IVLen:    16,
		HashFunc: sha256.New,
		IsAEAD:   false,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:       tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		Name:     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		Version:  TLSVersion12,
		KeyLen:   32,
		MacLen:   20,
		IVLen:    16,
		HashFunc: sha256.New,
		IsAEAD:   false,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:       tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		Name:     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		Version:  TLSVersion12,
		KeyLen:   16,
		MacLen:   20,
		IVLen:    16,
		HashFunc: sha256.New,
		IsAEAD:   false,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:       tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		Name:     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		Version:  TLSVersion12,
		KeyLen:   32,
		MacLen:   20,
		IVLen:    16,
		HashFunc: sha256.New,
		IsAEAD:   false,
	})

	// TLS 1.2 GCM 密码套件
	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Name:        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		Version:     TLSVersion12,
		KeyLen:      16,
		MacLen:      0,
		IVLen:       4,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		Name:        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Version:     TLSVersion12,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       4,
		HashFunc:    sha512.New384,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		Name:        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		Version:     TLSVersion12,
		KeyLen:      16,
		MacLen:      0,
		IVLen:       4,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		Name:        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		Version:     TLSVersion12,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       4,
		HashFunc:    sha512.New384,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		Name:        "TLS_RSA_WITH_AES_128_GCM_SHA256",
		Version:     TLSVersion12,
		KeyLen:      16,
		MacLen:      0,
		IVLen:       4,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		Name:        "TLS_RSA_WITH_AES_256_GCM_SHA384",
		Version:     TLSVersion12,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       4,
		HashFunc:    sha512.New384,
		IsAEAD:      true,
		AEADFactory: newAESGCMCipher,
	})

	// TLS 1.2 ChaCha20 密码套件
	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		Name:        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		Version:     TLSVersion12,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       12,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newChaCha20Poly1305Cipher,
	})

	RegisterCipherSuite(&CipherSuiteConfig{
		ID:          tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		Name:        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		Version:     TLSVersion12,
		KeyLen:      32,
		MacLen:      0,
		IVLen:       12,
		HashFunc:    sha256.New,
		IsAEAD:      true,
		AEADFactory: newChaCha20Poly1305Cipher,
	})
}
