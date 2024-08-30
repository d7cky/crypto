package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/minio/sio"
	"github.com/shirou/gopsutil/cpu"
)

func encryptFile(inputFile, outputFile string, key []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	config := sio.Config{Key: key}
	writer, err := sio.EncryptWriter(outFile, config)
	if err != nil {
		return err
	}
	defer writer.Close()

	_, err = io.Copy(writer, inFile)
	return err
}

func decryptFile(inputFile, outputFile string, key []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	config := sio.Config{Key: key}
	reader, err := sio.DecryptReader(inFile, config)
	if err != nil {
		return err
	}

	_, err = io.Copy(outFile, reader)
	return err
}

func measurePerformance(f func()) (time.Duration, float64, float64) {
	start := time.Now()

	// CPU and memory usage before
	cpuPercentCh := make(chan float64, 1)
	memUsedCh := make(chan float64, 1)

	go func() {
		percent, _ := cpu.Percent(500*time.Millisecond, false) // lấy mẫu CPU mỗi 500ms
		totalCPU := 0.0
		for _, p := range percent {
			totalCPU += p
		}
		cpuPercentCh <- totalCPU / float64(len(percent)) // tính trung bình CPU usage
	}()

	go func() {
		memUsageSum := 0.0
		count := 0
		for {
			memStats := &runtime.MemStats{}
			runtime.ReadMemStats(memStats)
			memUsageSum += float64(memStats.HeapAlloc) / (1024 * 1024) // Đổi sang MB
			count++
			select {
			case <-time.After(500 * time.Millisecond):
				// Break the loop when f() finishes
			case <-memUsedCh:
				memUsedCh <- memUsageSum / float64(count)
				return
			}
		}
	}()

	f()

	elapsed := time.Since(start)
	cpuPercentUsed := <-cpuPercentCh

	memUsedCh <- 0 
	memUsed := <-memUsedCh   

	return elapsed, cpuPercentUsed, memUsed
}

func generateKeyFromPassword(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func main() {
	password := "Vpbank@123"
	key := generateKeyFromPassword(password) // Tạo khóa từ mật khẩu

	fmt.Println("Starting encryption...")
	encryptDuration, encryptCpuUsage, encryptMemUsed := measurePerformance(func() {
		err := encryptFile("../../6_1.csv", "example.enc", key)
		if err != nil {
			log.Fatal(err)
		}
	})
	fmt.Printf("File encrypted successfully in %v\n", encryptDuration)
	fmt.Printf("Encryption CPU usage: %.2f%%\n", encryptCpuUsage)
	fmt.Printf("Encryption memory used: %.2f MB\n", encryptMemUsed)

	fmt.Println("Starting decryption...")
	decryptDuration, decryptCpuUsage, decryptMemUsed := measurePerformance(func() {
		err := decryptFile("example.enc", "board_contents.csv", key)
		if err != nil {
			log.Fatal(err)
		}
	})
	fmt.Printf("File decrypted successfully in %v\n", decryptDuration)
	fmt.Printf("Decryption CPU usage: %.2f%%\n", decryptCpuUsage)
	fmt.Printf("Decryption memory used: %.2f MB\n", decryptMemUsed)
}
