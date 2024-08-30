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
***

# Golang crypto/aes
## crypto/aes
### Bước 1: Tải và cài đặt thư viện crypto/aes
**Do đây là thư viện tích hợp sẵn trong ngôn ngữ Golang nên việc cài đặt chỉ đơn giản là cài đặt ngôn ngữ Golang**.
- **Tải và cài đặt Go**: Nếu bạn chưa có Go trên hệ thống của mình, hãy tải và cài đặt nó từ trang web chính thức: [golang.org/dl](https://golang.org/dl/).
- **Thiết lập biến môi trường**: Đảm bảo rằng biến môi trường `GOPATH` được thiết lập đúng cách. Bạn có thể kiểm tra bằng cách chạy `go env` trong terminal để xem cấu hình hiện tại.
### Bước 2: Code mẫu để mã hoá/giải mã file.
- [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Golang/crypto_aes)
### Bước 3: Biên dịch và chạy chương trình
#### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
go run main.go
```
#### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
go build -o main main.go
```
**Chạy chương trình**
```
./main
```
## github.com/minio/sio
### Bước 1: Tải và cài đặt thư viện github.com/minio/sio
**Cài đặt thư viện sử dụng `go get`**
```
go get github.com/minio/sio
```
*Nếu không sử dụng được `go get` thì bạn có thể sử dụng `go mod` để quản lý các thư viện phụ thuộc của dự án*
**1. Khởi tạo một module nếu chưa có**
```
go mod init your-module-name
```
**2. Thêm các thư viện phụ thuộc vào module**
```
go get github.com/minio/sio
```
### Bước 2: Code mẫu để mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Golang/minio_sio)
### Bước 3: Biên dịch và chạy chương trình
#### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
go run main.go
```
#### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
go build -o main main.go
```
**Chạy chương trình**
```
./main
```
***

# C# 
## System.Security.Cryptography
## Bước 1: Tạo dự án mới
- Sử dụng lệnh sau để tạo dự án mới với C# console.
```
dotnet new console -n CryptoExample
```
- Di chuyển vào thư mục dự án.
```
cd CryptoExample
```
### Bước 2: Tải và cài đặt thư viện
- Thêm thư viện `System.Security.Cryptography` nếu chưa có sẵn:
```
dotnet add package System.Security.Cryptography.Algorithms
```
### Bước 3: Code mẫu mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/C%23/CryptoExample)
### Bước 4: Biên dịch và chạy chương trình
#### #### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
dotnet run
```
#### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
dotnet build
```
*File .dll được tạo ra trong thư mục bin của project*
## BouncyCastle
## Bước 1: Tạo dự án mới
- Sử dụng lệnh sau để tạo dự án mới với C# console.
```
dotnet new console -n BouncyCastle
```
- Di chuyển vào thư mục dự án.
```
cd CryptoExample
```
### Bước 2: Tải và cài đặt thư viện
- Thêm thư viện `BouncyCastle.NetCore` nếu chưa có sẵn:
```
dotnet add package BouncyCastle.NetCore
```
### Bước 3: Code mẫu mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/C%23/BouncyCastle)
### Bước 4: Biên dịch và chạy chương trình
#### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
dotnet run
```
#### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
dotnet build
```
*File .dll được tạo ra trong thư mục bin của project*
## Libsodium
## Bước 1: Tạo dự án mới
- Sử dụng lệnh sau để tạo dự án mới với C# console.
```
dotnet new console -n LibsodiumExample
```
- Di chuyển vào thư mục dự án.
```
cd LibsodiumExample
```
### Bước 2: Tải và cài đặt thư viện
- Thêm thư viện `Sodium.Core` nếu chưa có sẵn:
```
dotnet add package Sodium.Core
```
### Bước 3: Code mẫu mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/C%23/LibsodiumExample)
### Bước 4: Biên dịch và chạy chương trình
#### #### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
dotnet run
```
#### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
dotnet build
```
*File .dll được tạo ra trong thư mục bin của project*

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