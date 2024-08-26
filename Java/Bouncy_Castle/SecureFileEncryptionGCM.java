import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.security.Security;

public class SecureFileEncryptionGCM {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void encryptFile(String inputFile, String outputFile, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        // Tạo IV ngẫu nhiên
        byte[] iv = new byte[12]; // GCM thường sử dụng IV 12 byte
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // Tag size là 128 bit

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            // Ghi IV ra tệp trước
            fos.write(iv);

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
        String inputFile = "../../board_contents.csv";  // Đường dẫn đến tệp cần mã hóa
        String outputFile = "output.enc"; // Đường dẫn đến tệp đã mã hóa

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        encryptFile(inputFile, outputFile, secretKey);

        System.out.println("File encrypted successfully!");
    }
}
