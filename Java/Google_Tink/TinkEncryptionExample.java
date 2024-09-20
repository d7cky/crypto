import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.AesGcmJce;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.sun.management.OperatingSystemMXBean;

import java.io.File;
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
        // String inputFile = "../../../../Research/Dev_with_GPU/wordlist_hash/5_1.csv";
        // String encryptedFile = "encrypted.enc";
        // String decryptedFile = "decrypted.csv";

        String inputDir = "../../kgon-g";  // Đường dẫn đến thư mục cần mã hóa
        String encryptDir = "../../kgon-g-encrypt";  // Đường dẫn đến thư mục đã mã hóa
        String decryptDir = "../../kgon-g-decrypt";  // Đường dẫn đến thư mục đã giải mã

        // Đo thời gian chạy và sử dụng CPU/RAM trước khi chạy
        long startTime = System.currentTimeMillis();
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);

        double cpuLoadBefore = osBean.getProcessCpuLoad() * 100;
        long startMemoryUsage = osBean.getCommittedVirtualMemorySize();

        // Mã hóa tệp
        // encryptFile(inputFile, encryptedFile, aead);
        encryptDirectory(inputDir, encryptDir, aead);

        // Giải mã tệp
        // decryptFile(encryptedFile, decryptedFile, aead);
        decryptDirectory(encryptDir, decryptDir, aead);

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

    public static void encryptDirectory(String srcDirPath, String destDirPath, Aead key) throws Exception {
        File srcDirectory = new File(srcDirPath);
        if (!srcDirectory.isDirectory()) {
            throw new IllegalArgumentException("The provided source path is not a directory");
        }

        File[] files = srcDirectory.listFiles();
        if (files == null || files.length == 0) {
            throw new IllegalArgumentException("The source directory is empty or cannot be read");
        }

        for (File file : files) {
            if (file.isDirectory()) {
                String newDestDirPath = Paths.get(destDirPath, file.getName()).toString();
                Files.createDirectories(Paths.get(newDestDirPath));
                encryptDirectory(file.getAbsolutePath(), newDestDirPath, key);
            } else {
                String outputFilePath = Paths.get(destDirPath, file.getName() + ".enc").toString();
                encryptFile(file.getAbsolutePath(), outputFilePath, key);
                System.out.println("Encrypted file: " + file.getAbsolutePath());
            }
        }
    }

    public static void decryptDirectory(String srcDirPath, String destDirPath, Aead key) throws Exception {
        File srcDirectory = new File(srcDirPath);
        if (!srcDirectory.isDirectory()) {
            throw new IllegalArgumentException("The provided source path is not a directory");
        }

        File[] files = srcDirectory.listFiles();
        if (files == null || files.length == 0) {
            throw new IllegalArgumentException("The source directory is empty or cannot be read");
        }

        for (File file : files) {
            if (file.isDirectory()) {
                String newDestDirPath = Paths.get(destDirPath, file.getName()).toString();
                Files.createDirectories(Paths.get(newDestDirPath));
                decryptDirectory(file.getAbsolutePath(), newDestDirPath, key);
            } else {
                if (file.getName().endsWith(".enc")) {
                    String outputFilePath = Paths.get(destDirPath, file.getName().substring(0, file.getName().length() - 4)).toString();
                    decryptFile(file.getAbsolutePath(), outputFilePath, key);
                    System.out.println("Decrypted file: " + file.getAbsolutePath());
                }
            }
        }
    }
}
