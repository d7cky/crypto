import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.management.ManagementFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import com.sun.management.OperatingSystemMXBean;

public class SecureFileEncryptionGCM {

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

    public static SecretKey getKeyFromPassword(String password) throws Exception {
        // Sử dụng SHA-256 để băm mật khẩu thành khóa 256-bit
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes("UTF-8"));
        // Chuyển đổi thành SecretKeySpec cho AES
        return new SecretKeySpec(key, "AES");
    }

    public static void main(String[] args) throws Exception {
        String inputFile = "../../decrypted.csv";  // Đường dẫn đến tệp cần mã hóa
        String outputFile = "output.enc"; // Đường dẫn đến tệp đã mã hóa

        // Sử dụng chuỗi "Vpbank@123" để tạo khóa AES-256
        String password = "Vpbank@123";
        SecretKey secretKey = getKeyFromPassword(password);

        // Đo thời gian chạy và sử dụng CPU/RAM trước khi chạy
        long startTime = System.currentTimeMillis();
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);

        double cpuLoadBefore = osBean.getProcessCpuLoad() * 100;
        long startMemoryUsage = osBean.getCommittedVirtualMemorySize();

        // Mã hóa tệp
        encryptFile(inputFile, outputFile, secretKey);

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
