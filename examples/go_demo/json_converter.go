// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// json_converter.go - 将 DecryptedPacket 转换为 JSON 格式
package main

import (
	"encoding/json"
	"os"

	"github.com/cfc4n/ecapture_decryptor/types"
)

// saveAsJSON 将解密的包保存为 JSON 格式
func saveAsJSON(packets []*types.DecryptedPacket, filename string, verbose bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(packets)
}
