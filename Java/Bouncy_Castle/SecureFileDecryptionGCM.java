import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import com.sun.management.OperatingSystemMXBean;

public class SecureFileDecryptionGCM {

    static {
        Security.addProvider(new BouncyCastleProvider());
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
        byte[] key = sha.digest(password.getBytes(StandardCharsets.UTF_8));
        // Chuyển đổi thành SecretKeySpec cho AES
        return new SecretKeySpec(key, "AES");
    }

    public static void main(String[] args) throws Exception {
        String inputFile = "output.enc";  // Đường dẫn đến tệp đã mã hóa
        String outputFile = "decrypted.csv"; // Đường dẫn đến tệp giải mã

        // Sử dụng chuỗi "Vpbank@123" để tạo khóa AES-256
        String password = "Vpbank@123";
        SecretKey secretKey = getKeyFromPassword(password);

        // Đo thời gian chạy và sử dụng CPU/RAM trước khi chạy
        long startTime = System.currentTimeMillis();
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);

        double cpuLoadBefore = osBean.getProcessCpuLoad() * 100;
        long startMemoryUsage = osBean.getCommittedVirtualMemorySize();

        decryptFile(inputFile, outputFile, secretKey);

        // Đo thời gian chạy và sử dụng CPU/RAM sau khi chạy
        double cpuLoadAfter = osBean.getProcessCpuLoad() * 100;
        long endMemoryUsage = osBean.getCommittedVirtualMemorySize();
        long endTime = System.currentTimeMillis();

        // In ra các kết quả đo
        System.out.println("Time taken: " + (endTime - startTime) + " ms");
        System.out.println("CPU load during execution: " + ((cpuLoadAfter + cpuLoadBefore) / 2) + " %");
        System.out.println("RAM used: " + (endMemoryUsage - startMemoryUsage) / (1024 * 1024) + " MB");

        System.out.println("File decrypted successfully!");
    }
}
