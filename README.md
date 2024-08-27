# JAVA 
## Bouncy Castle
### Bước 1: Tải và cài đặt thư viện Bouncy Castle vào dự án
* Truy cập vào [trang chủ Bouncy Castle](https://www.bouncycastle.org/download/bouncy-castle-java/#latest) để down load file .jar
* Copy/move file .jar vừa tải về vào thư mục dự án.
### Bước 2: Code mẫu để mã hoá/giải mã file.
* [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Java/Bouncy_Castle)
### Bước 3: Hướng dẫn run chương trình
* Biên dịch mã nguồn
```
javac -cp bcprov-jdk18on-1.78.1.jar SecureFileEncryptionGCM.java
```
* Chạy chương trình
```
java -cp :bcprov-jdk18on-1.78.1.jar SecureFileEncryptionGCM
```
## JCA/JCE
### Bước 1: Tải và cài đặt thư viện JCA/JCE vào dự án
* Do thư viện đã được tích hợp trong JAVA nên bạn chỉ cần tải và cài đặt JDK là sẽ có thể sử dụng được thư viện. [Tải JDK](https://www.oracle.com/java/technologies/downloads/#java11).
### Bước 2: Code mẫu để mã hoá/giải mã file.
* [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Java/JCAExample)
### Bước 3: Hướng dẫn run chương trình
* Biên dịch mã nguồn
```
javac FileEncryption.java
```
* Chạy chương trình
```
java FileEncryption
```
## Google Tink
### Bước 1: Tải và cài đặt thư viện Google Tink
#### Sử dụng Maven
* Nếu bạn đang sử dụng Maven, thêm phần phụ thuộc sau vào tệp `pom.xml` của bạn:
```
<dependencies>
    <dependency>
        <groupId>com.google.crypto.tink</groupId>
        <artifactId>tink</artifactId>
        <version>1.9.0</version> <!-- hoặc phiên bản mới nhất -->
    </dependency>
</dependencies>
```
#### Sử dụng Gradle
* Nếu bạn đang sử dụng Gradle, thêm phần phụ thuộc sau vào tệp `build.gradle`:
```
dependencies {
    implementation 'com.google.crypto.tink:tink:1.9.0' // hoặc phiên bản mới nhất
}
```
#### Tải JAR trực tiếp
Nếu bạn không sử dụng Maven hoặc Gradle, bạn có thể tải các tệp JAR từ trang [Maven Central Repository](https://repo1.maven.org/maven2/com/google/crypto/tink/tink/1.14.1/):

- Ngoài ra bạn cần tải thêm các thư viện phụ thuộc sau:
	- **Protobuf**: Tải xuống `protobuf-java` từ [Maven Central](https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.21.12/).
	- **Guava**: Tải xuống `guava` từ [Maven Central](https://repo1.maven.org/maven2/com/google/guava/guava/31.1-jre/).
	- **SLF4J**: Tải xuống `slf4j-api` từ [Maven Central](https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/).
	- **ErrorProne**: Tải xuống `error_prone_annotations` từ [Maven Central](https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.11.0/).
- Thêm các tệp JAR đã tải vào classpath của dự án Java của bạn.
### Bước 2: Code mẫu để mã hoá/giải mã
- [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Java/Google_Tink)
### Bước 3: Hướng dẫn run chương trình
* Biên dịch mã nguồn
```
javac -cp :tink-1.14.1.jar:protobuf-java-3.21.12.jar:guava-31.1-jre.jar:slf4j-api-1.7.36.jar:error_prone_annotations-2.11.0.jar TinkEncryptionExample.java
```
* Chạy chương trình
```
java -cp :tink-1.14.1.jar:protobuf-java-3.21.12.jar:guava-31.1-jre.jar:slf4j-api-1.7.36.jar:error_prone_annotations-2.11.0.jar TinkEncryptionExample
```
# Golang crypto/aes
So sánh các thư viện

| Thư viện                 | Tính năng                                  | Tốc độ                                    | Bảo mật                                   |
| ------------------------ | ------------------------------------------ | ----------------------------------------- | ----------------------------------------- |
| crypto/aes               | Hỗ trợ nhiều mode mã hoá                   | Rất nhanh (đặc biệt với AES-NI)           | Rất cao, do đội ngũ phát triển Go duy trì |
| github.com/minio/sio     | Dễ sử dụng, hỗ trợ đa số các mode phổ biến | Tốc độ tốt                                | Rất cao, bảo mật và xác thực tốt          |
| github.com/aead/chacha20 | Hỗ trợ mode Chacha20-Poly1305              | Rất nhanh, đặc biệt trên thiết bị di động | Rất cao, tương đương AES-GCM              |

## Code mẫu để mã hoá/giải mã file.
```
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
```

# C# BouncyCastle
So sánh các thư viện

| Thư viện                     | Tính năng                                       | Tốc độ                                     | Bảo mật                                                  |
| ---------------------------- | ----------------------------------------------- | ------------------------------------------ | -------------------------------------------------------- |
| System.Security.Cryptography | Các thuật toán mã hóa chuẩn                     | Rất nhanh, tối ưu tốt với AES-NI           | Rất cao, tiêu chuẩn trong .NET                           |
| BouncyCastle                 | Nhiều thuật toán mã hóa khác nhau               | Tốc độ tốt, nhưng có thể chậm hơn một chút | Rất cao, được cập nhật liên tục                          |
| NaCl (libsodium)             | Mã hóa, xác thực, và sinh số ngẫu nhiên an toàn | Rất nhanh, đặc biệt với ChaCha20           | Rất cao, được thiết kế để chống lại các lỗ hổng phổ biến |
## Bước 1: Tạo dự án C# 
``dotnet new console -n CryptoExample
``cd CryptoExample

## Bước 2: Code mẫu mã hoá/giải mã
```
using System;

using System.IO;

using System.Text;

using Org.BouncyCastle.Crypto;

using Org.BouncyCastle.Crypto.Engines;

using Org.BouncyCastle.Crypto.Modes;

using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Security;

  

class Program

{

static void Main()

{

string inputFile = "../../board_contents.csv"; // Tệp cần mã hóa

string encryptedFile = "example.enc"; // Tệp đã mã hóa

string decryptedFile = "board_contents.csv"; // Tệp sau khi giải mã

byte[] key = GenerateKeyFromPassword("Vpbank@123", 16); // Khóa AES 128-bit (16 byte)

byte[] iv = GenerateIV(); // Nonce/IV 12 byte cho GCM

  

// Mã hóa tệp

EncryptFile(inputFile, encryptedFile, key, iv);

Console.WriteLine($"File '{inputFile}' has been encrypted to '{encryptedFile}'.");

  

// Giải mã tệp

DecryptFile(encryptedFile, decryptedFile, key, iv);

Console.WriteLine($"File '{encryptedFile}' has been decrypted to '{decryptedFile}'.");

}

  

static byte[] GenerateKeyFromPassword(string password, int keySize)

{

byte[] key = new byte[keySize];

byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

  

// Copy passwordBytes vào key, nếu passwordBytes ngắn hơn keySize thì key sẽ được padding với 0

Array.Copy(passwordBytes, key, Math.Min(passwordBytes.Length, key.Length));

  

return key;

}

  

static byte[] GenerateIV()

{

var iv = new byte[12]; // 96-bit nonce

new SecureRandom().NextBytes(iv);

return iv;

}

  

static void EncryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)

{

AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv);

GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());

cipher.Init(true, parameters);

  

using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))

using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))

{

// Ghi IV vào tệp mã hóa để sử dụng khi giải mã

fsOutput.Write(iv, 0, iv.Length);

  

byte[] buffer = new byte[4096];

int bytesRead;

  

while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)

{

byte[] outputBytes = new byte[cipher.GetOutputSize(bytesRead)];

int outputLength = cipher.ProcessBytes(buffer, 0, bytesRead, outputBytes, 0);

if (outputLength > 0)

{

fsOutput.Write(outputBytes, 0, outputLength);

}

}

  

byte[] finalBytes = new byte[cipher.GetOutputSize(0)];

int finalLength = cipher.DoFinal(finalBytes, 0);

if (finalLength > 0)

{

fsOutput.Write(finalBytes, 0, finalLength);

}

}

}

  

static void DecryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)

{

AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv);

GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());

cipher.Init(false, parameters);

  

using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))

using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))

{

// Đọc IV từ tệp mã hóa

fsInput.Read(iv, 0, iv.Length);

  

byte[] buffer = new byte[4096];

int bytesRead;

  

while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)

{

byte[] outputBytes = new byte[cipher.GetOutputSize(bytesRead)];

int outputLength = cipher.ProcessBytes(buffer, 0, bytesRead, outputBytes, 0);

if (outputLength > 0)

{

fsOutput.Write(outputBytes, 0, outputLength);

}

}

  

byte[] finalBytes = new byte[cipher.GetOutputSize(0)];

int finalLength = cipher.DoFinal(finalBytes, 0);

if (finalLength > 0)

{

fsOutput.Write(finalBytes, 0, finalLength);

}

}

}

}
```
# Python PyCryptodome
So sánh các thư viện

| Thư viện     | Tính năng                               | Tốc độ                              | Bảo mật                                |
| ------------ | --------------------------------------- | ----------------------------------- | -------------------------------------- |
| PyCryptodome | Đầy đủ các thuật toán và chế độ mã hóa  | Nhanh, tối ưu hóa tốt               | Rất cao, thường xuyên được cập nhật    |
| cryptography | Được xây dựng trên OpenSSL, API dễ dùng | Rất nhanh, tận dụng OpenSSL         | Rất cao, tiêu chuẩn công nghiệp        |
| M2Crypto     | Wrapper cho OpenSSL                     | Nhanh, nhưng có lớp wrapper bổ sung | Cao, nhưng ít phổ biến hơn             |
| Fernet       | Dễ sử dụng, đảm bảo tính bảo mật        | Chậm hơn, nhưng vẫn đủ nhanh        | Rất cao, tránh các lỗi mã hóa phổ biến |
## Bước 1: Cài đặt thư viện PyCryptodome
``pip install pycryptodome
## Bước 2: Code mẫu mã hoá/giải mã
```
import sys

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes

import hashlib

import os

  

# Đảm bảo in ra console với mã hóa UTF-8

sys.stdout.reconfigure(encoding='utf-8')

  

def get_key_from_password(password):

# Sử dụng SHA-256 để băm chuỗi khóa thành 32 byte (256 bit)

return hashlib.sha256(password.encode()).digest()

  

def encrypt_file(file_name, password):

key = get_key_from_password(password)

# Đọc dữ liệu từ tệp

with open(file_name, 'rb') as f:

plaintext = f.read()

  

# Tạo nonce (IV) ngẫu nhiên

nonce = get_random_bytes(12)

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

  

# Mã hóa dữ liệu và tạo tag xác thực

ciphertext, tag = cipher.encrypt_and_digest(plaintext)

  

# Đặt tên tệp mã hóa

output_file = os.path.splitext(file_name)[0] + '.enc'

  

# Ghi nonce, tag và ciphertext vào tệp mã hóa

with open(output_file, 'wb') as f:

f.write(nonce + tag + ciphertext)

  

print(f"File '{file_name}' đã được mã hóa thành '{output_file}'.")

  

def decrypt_file(file_name, password):

key = get_key_from_password(password)

  

# Đọc nonce, tag và ciphertext từ tệp mã hóa

with open(file_name, 'rb') as f:

nonce = f.read(12)

tag = f.read(16)

ciphertext = f.read()

  

# Tạo cipher để giải mã

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

  

# Giải mã dữ liệu và xác thực tag

try:

plaintext = cipher.decrypt_and_verify(ciphertext, tag)

except ValueError:

print("Giải mã thất bại hoặc tag không hợp lệ!")

return

  

# Đặt tên tệp đã giải mã

output_file = os.path.splitext(file_name)[0] + '_decrypted.csv'

  

# Ghi dữ liệu đã giải mã vào tệp mới

with open(output_file, 'wb') as f:

f.write(plaintext)

  

print(f"File '{file_name}' đã được giải mã thành '{output_file}'.")

  

if __name__ == '__main__':

# Chuỗi khóa do người dùng chọn

password = "Vpbank@123"

  

# Tên tệp cần mã hóa

original_file = '../board_contents.csv'

  

# Mã hóa tệp

encrypt_file(original_file, password)

  

# Giải mã tệp

encrypted_file = os.path.splitext(original_file)[0] + '.enc'

decrypt_file(encrypted_file, password)
```
# Groovy BouncyCastle
So sánh các thư viện

| Thư viện                  | Tính năng                              | Tốc độ                                      | Bảo mật                                   |
| ------------------------- | -------------------------------------- | ------------------------------------------- | ----------------------------------------- |
| Java's Standard Libraries | Mã hóa tiêu chuẩn, tích hợp trong Java | Rất nhanh, tối ưu hóa tốt                   | Rất cao, tiêu chuẩn trong Java            |
| BouncyCastle              | Hỗ trợ nhiều thuật toán, đa dạng       | Tốt, nhưng chậm hơn so với chuẩn            | Rất cao, đặc biệt với thuật toán phức tạp |
| Apache Shiro              | Quản lý người dùng, kiểm soát truy cập | Tốt, nhưng không tối ưu hóa cho mã hóa mạnh | Cao, phù hợp với ứng dụng web             |
## Code mẫu mã hoá/giải mã
```
@Grab(group='org.bouncycastle', module='bcprov-jdk15on', version='1.70')

  

import org.bouncycastle.jce.provider.BouncyCastleProvider

import org.bouncycastle.crypto.engines.AESEngine

import org.bouncycastle.crypto.modes.GCMBlockCipher

import org.bouncycastle.crypto.params.AEADParameters

import org.bouncycastle.crypto.params.KeyParameter

import java.security.Security

import java.security.SecureRandom

import java.nio.file.Files

import java.nio.file.Paths

  

// Đăng ký BouncyCastle như là một nhà cung cấp bảo mật

Security.addProvider(new BouncyCastleProvider())

  

// Chuyển đổi chuỗi mật khẩu thành khóa AES

def getKeyFromPassword(String password, int length = 16) {

def keyBytes = password.bytes

def key = new byte[length]

Arrays.fill(key, (byte) 0)

System.arraycopy(keyBytes, 0, key, 0, Math.min(keyBytes.length, length))

return key

}

  

// Hàm nối hai mảng byte

def byte[] concatByteArrays(byte[] a, byte[] b) {

def result = new byte[a.length + b.length]

System.arraycopy(a, 0, result, 0, a.length)

System.arraycopy(b, 0, result, a.length, b.length)

return result

}

  

// Mã hóa tệp

def encryptFile(String inputFilePath, String outputFilePath, byte[] key) {

def iv = new byte[12] // 96-bit nonce

new SecureRandom().nextBytes(iv)

  

def cipher = new GCMBlockCipher(new AESEngine())

def params = new AEADParameters(new KeyParameter(key), 128, iv)

cipher.init(true, params)

  

def inputBytes = Files.readAllBytes(Paths.get(inputFilePath))

  

def cipherText = new byte[cipher.getOutputSize(inputBytes.length)]

def len = cipher.processBytes(inputBytes, 0, inputBytes.length, cipherText, 0)

cipher.doFinal(cipherText, len)

  

// Ghi nonce và ciphertext vào tệp mã hóa

def outputBytes = concatByteArrays(iv, cipherText)

Files.write(Paths.get(outputFilePath), outputBytes)

  

println "File '${inputFilePath}' đã được mã hóa thành '${outputFilePath}'."

}

  

// Giải mã tệp

def decryptFile(String inputFilePath, String outputFilePath, byte[] key) {

def inputBytes = Files.readAllBytes(Paths.get(inputFilePath))

  

// Chuyển đổi đoạn slice thành mảng byte thay vì danh sách

def iv = inputBytes[0..11] as byte[] // 12 byte đầu tiên là nonce

def cipherText = inputBytes[12..-1] as byte[]

  

def cipher = new GCMBlockCipher(new AESEngine())

def params = new AEADParameters(new KeyParameter(key), 128, iv)

cipher.init(false, params)

  

def plainText = new byte[cipher.getOutputSize(cipherText.length)]

def len = cipher.processBytes(cipherText, 0, cipherText.length, plainText, 0)

cipher.doFinal(plainText, len)

  

// Ghi dữ liệu đã giải mã vào tệp đầu ra

Files.write(Paths.get(outputFilePath), plainText)

  

println "File '${inputFilePath}' đã được giải mã thành '${outputFilePath}'."

}

  

// Sử dụng chuỗi "Vpbank@123" làm khóa

def password = "Vpbank@123"

def key = getKeyFromPassword(password)

  

// Đường dẫn tệp gốc và tệp mã hóa

def inputFile = "../../board_contents.csv"

def encryptedFile = "board_contents.enc"

def decryptedFile = "board_contents_decrypted.csv"

  

// Mã hóa tệp

encryptFile(inputFile, encryptedFile, key)

  

// Giải mã tệp

decryptFile(encryptedFile, decryptedFile, key)
```