using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Program
{
    static void Main()
    {
        string inputFile = "../../board_contents.csv";           // Tệp cần mã hóa
        string encryptedFile = "example.enc";       // Tệp đã mã hóa
        string decryptedFile = "board_contents.csv";   // Tệp sau khi giải mã
        byte[] key = GenerateKeyFromPassword("Vpbank@123", 16); // Khóa AES 128-bit (16 byte)
        byte[] iv = GenerateIV();                   // Nonce/IV 12 byte cho GCM

        // Mã hóa tệp
        EncryptFile(inputFile, encryptedFile, key, iv);
        Console.WriteLine($"File '{inputFile}' has been encrypted to '{encryptedFile}'.");

        // Giải mã tệp
        DecryptFile(encryptedFile, decryptedFile, key, iv);
        Console.WriteLine($"File '{encryptedFile}' has been decrypted to '{decryptedFile}'.");
    }

    static byte[] GenerateKeyFromPassword(string password, int keySize)
    {
        byte[] key = new byte[keySize];
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        // Copy passwordBytes vào key, nếu passwordBytes ngắn hơn keySize thì key sẽ được padding với 0
        Array.Copy(passwordBytes, key, Math.Min(passwordBytes.Length, key.Length));

        return key;
    }

    static byte[] GenerateIV()
    {
        var iv = new byte[12]; // 96-bit nonce
        new SecureRandom().NextBytes(iv);
        return iv;
    }

    static void EncryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
    {
        AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv);
        GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(true, parameters);

        using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
        {
            // Ghi IV vào tệp mã hóa để sử dụng khi giải mã
            fsOutput.Write(iv, 0, iv.Length);

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
            {
                byte[] outputBytes = new byte[cipher.GetOutputSize(bytesRead)];
                int outputLength = cipher.ProcessBytes(buffer, 0, bytesRead, outputBytes, 0);
                if (outputLength > 0)
                {
                    fsOutput.Write(outputBytes, 0, outputLength);
                }
            }

            byte[] finalBytes = new byte[cipher.GetOutputSize(0)];
            int finalLength = cipher.DoFinal(finalBytes, 0);
            if (finalLength > 0)
            {
                fsOutput.Write(finalBytes, 0, finalLength);
            }
        }
    }

    static void DecryptFile(string inputFile, string outputFile, byte[] key, byte[] iv)
    {
        AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv);
        GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, parameters);

        using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
        {
            // Đọc IV từ tệp mã hóa
            fsInput.Read(iv, 0, iv.Length);

            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
            {
                byte[] outputBytes = new byte[cipher.GetOutputSize(bytesRead)];
                int outputLength = cipher.ProcessBytes(buffer, 0, bytesRead, outputBytes, 0);
                if (outputLength > 0)
                {
                    fsOutput.Write(outputBytes, 0, outputLength);
                }
            }

            byte[] finalBytes = new byte[cipher.GetOutputSize(0)];
            int finalLength = cipher.DoFinal(finalBytes, 0);
            if (finalLength > 0)
            {
                fsOutput.Write(finalBytes, 0, finalLength);
            }
        }
    }
}
