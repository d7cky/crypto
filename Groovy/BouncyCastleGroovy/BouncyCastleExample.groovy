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
