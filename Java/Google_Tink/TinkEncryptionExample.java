import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.AesGcmJce;

import javax.crypto.spec.SecretKeySpec;
import com.sun.management.OperatingSystemMXBean;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

public class TinkEncryptionExample {

    public static void main(String[] args) throws Exception {
        // Đăng ký cấu hình mã hóa mặc định cho Tink
        AeadConfig.register();

        // Sử dụng chuỗi "Vpbank@123" để tạo khóa AES-256
        String password = "Vpbank@123";
        Aead aead = createAeadFromPassword(password);

        // Tệp đầu vào và tệp kết quả
        String inputFile = "../../../../Research/Dev_with_GPU/wordlist_hash/5_1.csv";
        String encryptedFile = "encrypted.enc";
        String decryptedFile = "decrypted.csv";

        // Đo thời gian chạy và sử dụng CPU/RAM trước khi chạy
        long startTime = System.currentTimeMillis();
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);

        double cpuLoadBefore = osBean.getProcessCpuLoad() * 100;
        long startMemoryUsage = osBean.getCommittedVirtualMemorySize();

        // Mã hóa tệp
        encryptFile(inputFile, encryptedFile, aead);

        // Giải mã tệp
        decryptFile(encryptedFile, decryptedFile, aead);

        // Đo thời gian chạy và sử dụng CPU/RAM sau khi chạy
        double cpuLoadAfter = osBean.getProcessCpuLoad() * 100;
        long endMemoryUsage = osBean.getCommittedVirtualMemorySize();
        long endTime = System.currentTimeMillis();

        // In ra các kết quả đo
        System.out.println("Time taken: " + (endTime - startTime) + " ms");
        System.out.println("CPU load during execution: " + ((cpuLoadAfter + cpuLoadBefore) / 2) + " %");
        System.out.println("RAM used: " + (endMemoryUsage - startMemoryUsage) / (1024 * 1024) + " MB");

        System.out.println("Encryption and Decryption completed successfully!");
    }

    public static Aead createAeadFromPassword(String password) throws Exception {
        // Sử dụng SHA-256 để băm mật khẩu thành khóa 256-bit
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes(StandardCharsets.UTF_8));

        // Tạo khóa AES-GCM từ mảng byte 256-bit
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        return new AesGcmJce(keySpec.getEncoded());
    }

    public static void encryptFile(String inputFile, String outputFile, Aead aead) throws Exception {
        // Đọc toàn bộ nội dung tệp
        byte[] plaintext = Files.readAllBytes(Paths.get(inputFile));

        // Mã hóa dữ liệu
        byte[] ciphertext = aead.encrypt(plaintext, null);

        // Ghi dữ liệu đã mã hóa vào tệp đầu ra
        Files.write(Paths.get(outputFile), ciphertext);
    }

    public static void decryptFile(String inputFile, String outputFile, Aead aead) throws Exception {
        // Đọc toàn bộ nội dung tệp mã hóa
        byte[] ciphertext = Files.readAllBytes(Paths.get(inputFile));

        // Giải mã dữ liệu
        byte[] plaintext = aead.decrypt(ciphertext, null);

        // Ghi dữ liệu đã giải mã vào tệp đầu ra
        Files.write(Paths.get(outputFile), plaintext);
    }
}
