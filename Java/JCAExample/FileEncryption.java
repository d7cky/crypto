import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

public class FileEncryption {
    public static void main(String[] args) throws Exception {
        // Sử dụng chuỗi khóa "Vpbank@123"
        String password = "Vpbank@123";
        SecretKey key = getKeyFromPassword(password, 256);

        // Đường dẫn đến tệp cần mã hóa và tệp kết quả
        String inputFile = "../../decrypted.csv";  // Tệp đầu vào cần mã hóa
        String encryptedFile = "encrypted.enc";
        String decryptedFile = "decrypted.csv";

        // Đo thời gian chạy và sử dụng CPU/RAM trước khi chạy
        long startTime = System.currentTimeMillis();
        OperatingSystemMXBean osBean = ManagementFactory.getPlatformMXBean(OperatingSystemMXBean.class);

        double cpuLoadBefore = osBean.getProcessCpuLoad() * 100;
        long startMemoryUsage = osBean.getCommittedVirtualMemorySize();

        // Mã hóa tệp
        encryptFile(key, inputFile, encryptedFile);

        // Giải mã tệp
        decryptFile(key, encryptedFile, decryptedFile);

        // Đo thời gian chạy và sử dụng CPU/RAM sau khi chạy
        double cpuLoadAfter = osBean.getProcessCpuLoad() * 100;
        long endMemoryUsage = osBean.getCommittedVirtualMemorySize();
        long endTime = System.currentTimeMillis();

        // In ra các kết quả đo
        System.out.println("Time taken: " + (endTime - startTime) + " ms");
        System.out.println("CPU load during execution: " + ((cpuLoadAfter + cpuLoadBefore) / 2) + " %");
        System.out.println("RAM used: " + (endMemoryUsage - startMemoryUsage) / (1024 * 1024) + " MB");
    }

    public static SecretKey getKeyFromPassword(String password, int keySize) throws Exception {
        // Tạo khóa AES từ mật khẩu sử dụng SHA-256 để băm mật khẩu
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = sha.digest(password.getBytes("UTF-8"));
        byte[] keyBytes = new byte[keySize / 8]; // keySize / 8 để chuyển đổi từ bit sang byte
        System.arraycopy(key, 0, keyBytes, 0, keyBytes.length);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static void encryptFile(SecretKey key, String inputFile, String outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV(); // Lấy IV (nonce)
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            // Ghi IV vào đầu tệp mã hóa
            fos.write(iv);

            byte[] buffer = new byte[1024 * 1024];  // Sử dụng khối 1MB
            int bytesRead;

            // Đọc và mã hóa từng khối dữ liệu
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

    public static void decryptFile(SecretKey key, String inputFile, String outputFile) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] iv = new byte[12];
            fis.read(iv); // Đọc IV từ đầu tệp mã hóa

            // Sử dụng GCMParameterSpec với tag 128-bit và khóa 256-bit
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

            byte[] buffer = new byte[1024 * 1024];  // Sử dụng khối 1MB
            int bytesRead;

            // Đọc và giải mã từng khối dữ liệu
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
}
