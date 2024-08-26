import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;

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

    public static void main(String[] args) throws Exception {
        String inputFile = "output.enc";  // Đường dẫn đến tệp đã mã hóa
        String outputFile = "board_contents.csv"; // Đường dẫn đến tệp giải mã

        // Sử dụng chuỗi "VPB4nk@crypto" làm khóa bí mật
        String keyString = "VPB4nk@crypto123";
        byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);

        // Đảm bảo rằng khóa có độ dài phù hợp (16 byte cho AES-128)
        if (keyBytes.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes long for AES-128.");
        }

        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        decryptFile(inputFile, outputFile, secretKey);

        System.out.println("File decrypted successfully!");
    }
}
