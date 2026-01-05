// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.

// main.go - 示例程序 - 使用新的解密库API
package main

import (
	"flag"
	"log"
	"os"

	"github.com/cfc4n/ecapture_decryptor"
	"github.com/cfc4n/ecapture_decryptor/types"
)

func main() {
	pcapfile := flag.String("pcap", "", "pcap file")
	sslkeylog := flag.String("sslkeylog", "", "sslkeylog file")
	harOutput := flag.String("har", "", "output HAR file path (optional)")
	jsonOutput := flag.String("json", "", "output JSON file path (optional)")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	if *pcapfile == "" || *sslkeylog == "" {
		log.Println("Usage: ecapture_decryptor -pcap <file> -sslkeylog <file> [-har <output>] [-json <output>] [-v]")
		flag.Usage()
		os.Exit(1)
	}

	// 打开 SSL keylog 文件
	keylogFile, err := os.Open(*sslkeylog)
	if err != nil {
		log.Fatalf("Failed to open sslkeylog file: %v", err)
	}
	defer func() { _ = keylogFile.Close() }()

	// 打开 pcap 文件
	pcapFile, err := os.Open(*pcapfile)
	if err != nil {
		log.Fatalf("Failed to open pcap file: %v", err)
	}
	defer func() { _ = pcapFile.Close() }()

	// 创建解密包输出通道
	packetChan := make(chan *types.DecryptedPacket, 100)

	// 收集解密的包
	packets := make([]*types.DecryptedPacket, 0)
	doneChan := make(chan struct{})

	go func() {
		for packet := range packetChan {
			packets = append(packets, packet)
			if *verbose {
				log.Printf("Meta: %v",
					packet.Meta(),
				)
			}
		}
		close(doneChan)
	}()

	// 使用新的 API 进行解密
	if *verbose {
		log.Printf("Starting decryption: pcap=%s, keylog=%s", *pcapfile, *sslkeylog)
	}

	err = ecapture_decryptor.DecryptPcapFile(keylogFile, pcapFile, packetChan)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	// 关闭通道，等待处理完成
	close(packetChan)
	<-doneChan

	if *verbose {
		log.Printf("Decryption completed, total packets: %d", len(packets))
	}

	// 输出到 HAR 格式（如果指定）
	if *harOutput != "" && len(packets) > 0 {
		if err := saveAsHAR(packets, *harOutput, *verbose); err != nil {
			log.Fatalf("Failed to write HAR file: %v", err)
		}
		if *verbose {
			log.Printf("HAR file written to %s", *harOutput)
		}
	}

	// 输出到 JSON 格式（如果指定）
	if *jsonOutput != "" && len(packets) > 0 {
		if err := saveAsJSON(packets, *jsonOutput, *verbose); err != nil {
			log.Fatalf("Failed to write JSON file: %v", err)
		}
		if *verbose {
			log.Printf("JSON file written to %s", *jsonOutput)
		}
	}

	// 如果没有指定输出文件，打印统计信息
	if *harOutput == "" && *jsonOutput == "" {
		printStatistics(packets)
	}
}

// printStatistics 打印解密包的统计信息
func printStatistics(packets []*types.DecryptedPacket) {
	stats := make(map[string]int)
	for _, pkt := range packets {
		key := pkt.Protocol + "/" + pkt.Direction
		stats[key]++
	}

	log.Println("\n=== Decryption Statistics ===")
	log.Printf("Total packets: %d\n", len(packets))
	for key, count := range stats {
		log.Printf("  %s: %d", key, count)
	}
}
