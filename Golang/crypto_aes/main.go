package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"time"
	"io/ioutil"
	"path/filepath"
	"github.com/shirou/gopsutil/cpu"
)

func encryptFile(inputFile, outputFile string, key []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	if _, err := outFile.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

func decryptFile(inputFile, outputFile string, key []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(inFile, nonce); err != nil {
		return err
	}

	ciphertext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	if _, err := outFile.Write(plaintext); err != nil {
		return err
	}

	return nil
}

// Mã hóa tất cả các tệp trong một thư mục
func encryptDirectory(srcDir, destDir string, key []byte) error {
	// Lấy tất cả các tệp trong thư mục nguồn
	files, err := ioutil.ReadDir(srcDir)
	if err != nil {
		return err
	}

	// Duyệt qua từng tệp và mã hóa
	for _, file := range files {
		if !file.IsDir() { // Bỏ qua thư mục con
			srcFilePath := filepath.Join(srcDir, file.Name())
			destFilePath := filepath.Join(destDir, file.Name()+".enc")

			err := encryptFile(srcFilePath, destFilePath, key)
			if err != nil {
				return fmt.Errorf("error encrypting file %s: %v", srcFilePath, err)
			}
			fmt.Printf("Encrypted %s -> %s\n", srcFilePath, destFilePath)
		}
	}
	return nil
}

// Giải mã tất cả các tệp trong một thư mục
func decryptDirectory(srcDir, destDir string, key []byte) error {
	// Lấy tất cả các tệp trong thư mục nguồn
	files, err := ioutil.ReadDir(srcDir)
	if err != nil {
		return err
	}

	// Duyệt qua từng tệp và giải mã
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".enc" { // Bỏ qua thư mục con và chỉ giải mã tệp .enc
			srcFilePath := filepath.Join(srcDir, file.Name())
			destFileName := file.Name()[:len(file.Name())-4] // Bỏ phần đuôi .enc
			destFilePath := filepath.Join(destDir, destFileName)

			err := decryptFile(srcFilePath, destFilePath, key)
			if err != nil {
				return fmt.Errorf("error decrypting file %s: %v", srcFilePath, err)
			}
			fmt.Printf("Decrypted %s -> %s\n", srcFilePath, destFilePath)
		}
	}
	return nil
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

	// fmt.Println("Starting encryption...")
	// encryptDuration, encryptCpuUsage, encryptMemUsed := measurePerformance(func() {
	// 	err := encryptFile("../../3.csv", "example.enc", key)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// })
	// Mã hóa tất cả các tệp trong thư mục
	fmt.Println("Starting directory encryption...")
	encryptDuration, encryptCpuUsage, encryptMemUsed := measurePerformance(func() {
		err := encryptDirectory("../../kgon-g", "../../kgon-g-encrypt/", key)
		if err != nil {
			log.Fatal(err)
		}
	})
	fmt.Println("Directory encrypted successfully.")

	fmt.Printf("File encrypted successfully in %v\n", encryptDuration)
	fmt.Printf("Encryption CPU usage: %.2f%%\n", encryptCpuUsage)
	fmt.Printf("Encryption memory used: %.2f MB\n", encryptMemUsed)

	// fmt.Println("Starting decryption...")
	// decryptDuration, decryptCpuUsage, decryptMemUsed := measurePerformance(func() {
	// 	err := decryptFile("example.enc", "board_contents.csv", key)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// })
	// Giải mã tất cả các tệp trong thư mục
	fmt.Println("Starting directory decryption...")
	decryptDuration, decryptCpuUsage, decryptMemUsed := measurePerformance(func() {
		err := decryptDirectory("../../kgon-g-encrypt/", "../../kgon-g-decrypt/", key)
		if err != nil {
			log.Fatal(err)
		}
	})
	fmt.Println("Directory decrypted successfully.")
	fmt.Printf("File decrypted successfully in %v\n", decryptDuration)
	fmt.Printf("Decryption CPU usage: %.2f%%\n", decryptCpuUsage)
	fmt.Printf("Decryption memory used: %.2f MB\n", decryptMemUsed)
}
