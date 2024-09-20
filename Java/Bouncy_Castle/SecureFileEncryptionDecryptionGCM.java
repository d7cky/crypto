import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import com.sun.management.OperatingSystemMXBean;

public class SecureFileEncryptionDecryptionGCM {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void encryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {
        // Sử dụng AES/GCM/NoPadding với BouncyCastle provider
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        // Tạo IV ngẫu nhiên với độ dài 12 byte (96 bit)
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // Tag size là 128 bit

        // Khởi tạo cipher với chế độ mã hóa, khóa, và GCM parameter spec
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Ghi IV vào đầu tệp mã hóa để sử dụng khi giải mã
            fos.write(iv);

            byte[] buffer = new byte[1024];
            int bytesRead;

            // Đọc dữ liệu từ tệp đầu vào và mã hóa
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }

            // Ghi phần còn lại của dữ liệu mã hóa vào tệp đầu ra
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fos.write(outputBytes);
            }
        }
    }

    public static void decryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Đọc IV từ tệp
            byte[] iv = new byte[12];
            fis.read(iv);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    fos.write(output);
                }
            }

            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                fos.write(outputBytes);
            }
        }
    }

    public static SecretKey getKeyFromPassword(String password) throws Exception {
        // Sử dụng SHA-256 để băm mật khẩu thành khóa 256-bit
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes("UTF-8"));
        // Chuyển đổi thành SecretKeySpec cho AES
        return new SecretKeySpec(key, "AES");
    }

    public static void encryptDirectory(String srcDirPath, String destDirPath, SecretKey key) throws Exception {
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

    public static void decryptDirectory(String srcDirPath, String destDirPath, SecretKey key) throws Exception {
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

    public static void main(String[] args) throws Exception {
        String inputDir = "../../kgon-g";  // Đường dẫn đến thư mục cần mã hóa
        String encryptDir = "../../kgon-g-encrypt";  // Đường dẫn đến thư mục đã mã hóa
        String decryptDir = "../../kgon-g-decrypt";  // Đường dẫn đến thư mục đã giải mã
        // String encryptFile = "output.enc"; // Đường dẫn đến tệp đã mã hóa
        // String decryptFile = "decrypted.csv"; // Đường dẫn đến tệp đã giải mã

        // Sử dụng chuỗi "Vpbank@123" để tạo khóa AES-256
        String password = "Vpbank@123";
        SecretKey secretKey = getKeyFromPassword(password);

        // Đo thời gian chạy và sử dụng CPU/RAM trước khi chạy
        long startTime = System.currentTimeMillis();
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);

        double cpuLoadBefore = osBean.getProcessCpuLoad() * 100;
        long startMemoryUsage = osBean.getCommittedVirtualMemorySize();

        // Mã hóa tệp
        encryptDirectory(inputDir, encryptDir, secretKey);

        // Giải mã tệp
        decryptDirectory(encryptDir, decryptDir, secretKey);

        // Đo thời gian chạy và sử dụng CPU/RAM sau khi chạy
        double cpuLoadAfter = osBean.getProcessCpuLoad() * 100;
        long endMemoryUsage = osBean.getCommittedVirtualMemorySize();
        long endTime = System.currentTimeMillis();

        // In ra các kết quả đo
        System.out.println("Time taken: " + (endTime - startTime) + " ms");
        System.out.println("CPU load during execution: " + ((cpuLoadAfter + cpuLoadBefore) / 2) + " %");
        System.out.println("RAM used: " + (endMemoryUsage - startMemoryUsage) / (1024 * 1024) + " MB");

        System.out.println("File encrypted successfully!");
    }
}
