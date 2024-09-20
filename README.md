# Hướng dẫn sử dụng thư viện an toàn, tối ưu cho việc encrypt/decrypt của các ngôn ngữ.
+ [JAVA](https://github.com/d7cky/crypto?tab=readme-ov-file#java)
	+ [Bouncy Castle](https://github.com/d7cky/crypto?tab=readme-ov-file#bouncy-castle)
	+ [JCA/JCE](https://github.com/d7cky/crypto?tab=readme-ov-file#jcajce)
	+ [Google Tink](https://github.com/d7cky/crypto?tab=readme-ov-file#google-tink)
+ [Golang](https://github.com/d7cky/crypto?tab=readme-ov-file#golang)
	+ [crypto/aes](https://github.com/d7cky/crypto?tab=readme-ov-file#cryptoaes)
	+ [github.com/minio/sio](https://github.com/d7cky/crypto?tab=readme-ov-file#githubcomminiosio)
+ [C#](https://github.com/d7cky/crypto?tab=readme-ov-file#c)
	+ [System.Security.Cryptography](https://github.com/d7cky/crypto?tab=readme-ov-file#systemsecuritycryptography)
	+ [BouncyCastle](https://github.com/d7cky/crypto?tab=readme-ov-file#bouncycastle)
	+ [Libsodium](https://github.com/d7cky/crypto?tab=readme-ov-file#libsodium)
## *Bảng testcase so sánh tốc độ của các thư viện*
- Các bạn có thể xem [tại đây](https://github.com/d7cky/crypto/blob/main/SS.xlsx)
## JAVA 
### Bouncy Castle
#### Bước 1: Tải và cài đặt thư viện Bouncy Castle vào dự án
* Truy cập vào [trang chủ Bouncy Castle](https://www.bouncycastle.org/download/bouncy-castle-java/#latest) để down load file .jar
* Copy/move file .jar vừa tải về vào thư mục dự án.
#### Bước 2: Code mẫu để mã hoá/giải mã file.
* [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Java/Bouncy_Castle)
#### Bước 3: Hướng dẫn run chương trình
* Biên dịch mã nguồn
```
javac -cp bcprov-jdk18on-1.78.1.jar SecureFileEncryptionGCM.java
```
* Chạy chương trình
```
java -cp :bcprov-jdk18on-1.78.1.jar SecureFileEncryptionGCM
```
### JCA/JCE
#### Bước 1: Tải và cài đặt thư viện JCA/JCE vào dự án
* Do thư viện đã được tích hợp trong JAVA nên bạn chỉ cần tải và cài đặt JDK là sẽ có thể sử dụng được thư viện. [Tải JDK](https://www.oracle.com/java/technologies/downloads/#java11).
#### Bước 2: Code mẫu để mã hoá/giải mã file.
* [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Java/JCAExample)
#### Bước 3: Hướng dẫn run chương trình
* Biên dịch mã nguồn
```
javac FileEncryption.java
```
* Chạy chương trình
```
java FileEncryption
```
### Google Tink
#### Bước 1: Tải và cài đặt thư viện Google Tink
##### Sử dụng Maven
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
##### Sử dụng Gradle
* Nếu bạn đang sử dụng Gradle, thêm phần phụ thuộc sau vào tệp `build.gradle`:
```
dependencies {
    implementation 'com.google.crypto.tink:tink:1.9.0' // hoặc phiên bản mới nhất
}
```
##### Tải JAR trực tiếp
Nếu bạn không sử dụng Maven hoặc Gradle, bạn có thể tải các tệp JAR từ trang [Maven Central Repository](https://repo1.maven.org/maven2/com/google/crypto/tink/tink/1.14.1/):

- Ngoài ra bạn cần tải thêm các thư viện phụ thuộc sau:
	- **Protobuf**: Tải xuống `protobuf-java` từ [Maven Central](https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/3.21.12/).
	- **Guava**: Tải xuống `guava` từ [Maven Central](https://repo1.maven.org/maven2/com/google/guava/guava/31.1-jre/).
	- **SLF4J**: Tải xuống `slf4j-api` từ [Maven Central](https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/).
	- **ErrorProne**: Tải xuống `error_prone_annotations` từ [Maven Central](https://repo1.maven.org/maven2/com/google/errorprone/error_prone_annotations/2.11.0/).
- Thêm các tệp JAR đã tải vào classpath của dự án Java của bạn.
#### Bước 2: Code mẫu để mã hoá/giải mã
- [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Java/Google_Tink)
#### Bước 3: Hướng dẫn run chương trình
* Biên dịch mã nguồn
```
javac -cp :tink-1.14.1.jar:protobuf-java-3.21.12.jar:guava-31.1-jre.jar:slf4j-api-1.7.36.jar:error_prone_annotations-2.11.0.jar TinkEncryptionExample.java
```
* Chạy chương trình
```
java -cp :tink-1.14.1.jar:protobuf-java-3.21.12.jar:guava-31.1-jre.jar:slf4j-api-1.7.36.jar:error_prone_annotations-2.11.0.jar TinkEncryptionExample
```
***

## Golang
### crypto/aes
#### Bước 1: Tải và cài đặt thư viện crypto/aes
**Do đây là thư viện tích hợp sẵn trong ngôn ngữ Golang nên việc cài đặt chỉ đơn giản là cài đặt ngôn ngữ Golang**.
- **Tải và cài đặt Go**: Nếu bạn chưa có Go trên hệ thống của mình, hãy tải và cài đặt nó từ trang web chính thức: [golang.org/dl](https://golang.org/dl/).
- **Thiết lập biến môi trường**: Đảm bảo rằng biến môi trường `GOPATH` được thiết lập đúng cách. Bạn có thể kiểm tra bằng cách chạy `go env` trong terminal để xem cấu hình hiện tại.
#### Bước 2: Code mẫu để mã hoá/giải mã file.
- [Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Golang/crypto_aes)
#### Bước 3: Biên dịch và chạy chương trình
##### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
go run main.go
```
##### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
go build -o main main.go
```
**Chạy chương trình**
```
./main
```
### github.com/minio/sio
#### Bước 1: Tải và cài đặt thư viện github.com/minio/sio
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
#### Bước 2: Code mẫu để mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/Golang/minio_sio)
#### Bước 3: Biên dịch và chạy chương trình
##### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
go run main.go
```
##### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
go build -o main main.go
```
**Chạy chương trình**
```
./main
```
***

## C# 
### System.Security.Cryptography
### Bước 1: Tạo dự án mới
- Sử dụng lệnh sau để tạo dự án mới với C# console.
```
dotnet new console -n CryptoExample
```
- Di chuyển vào thư mục dự án.
```
cd CryptoExample
```
#### Bước 2: Tải và cài đặt thư viện
- Thêm thư viện `System.Security.Cryptography` nếu chưa có sẵn:
```
dotnet add package System.Security.Cryptography.Algorithms
```
#### Bước 3: Code mẫu mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/C%23/CryptoExample)
#### Bước 4: Biên dịch và chạy chương trình
##### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
dotnet run
```
##### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
dotnet build
```
*File .dll được tạo ra trong thư mục bin của project*
### BouncyCastle
#### Bước 1: Tạo dự án mới
- Sử dụng lệnh sau để tạo dự án mới với C# console.
```
dotnet new console -n BouncyCastle
```
- Di chuyển vào thư mục dự án.
```
cd CryptoExample
```
#### Bước 2: Tải và cài đặt thư viện
- Thêm thư viện `BouncyCastle.NetCore` nếu chưa có sẵn:
```
dotnet add package BouncyCastle.NetCore
```
#### Bước 3: Code mẫu mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/C%23/BouncyCastle)
#### Bước 4: Biên dịch và chạy chương trình
##### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
dotnet run
```
##### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
dotnet build
```
*File .dll được tạo ra trong thư mục bin của project*
### Libsodium
#### Bước 1: Tạo dự án mới
- Sử dụng lệnh sau để tạo dự án mới với C# console.
```
dotnet new console -n LibsodiumExample
```
- Di chuyển vào thư mục dự án.
```
cd LibsodiumExample
```
#### Bước 2: Tải và cài đặt thư viện
- Thêm thư viện `Sodium.Core` nếu chưa có sẵn:
```
dotnet add package Sodium.Core
```
#### Bước 3: Code mẫu mã hoá/giải mã
[Sample code Encrypt/Decrypt](https://github.com/d7cky/crypto/tree/main/C%23/LibsodiumExample)
#### Bước 4: Biên dịch và chạy chương trình
##### Cách 1: Biên dịch và chạy chương trình tạm thời
Sau khi viết mã, bạn có thể biên dịch và chạy chương trình với lệnh sau:
```
dotnet run
```
##### Cách 2: Biên dịch và chạy chương trình
**Biên dịch chương trình**
```
dotnet build
```
*File .dll được tạo ra trong thư mục bin của project*

