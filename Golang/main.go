package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "fmt"
    "io"
    "log"
    "os"
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

func main() {
    key := []byte("VPB4nk@crypto123") // Khóa 16 byte cho AES-128

    err := encryptFile("../board_contents.csv", "example.enc", key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("File encrypted successfully")

    err = decryptFile("example.enc", "board_contents.csv", key)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("File decrypted successfully")
}
