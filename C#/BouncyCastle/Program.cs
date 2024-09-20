using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Program
{
    static void Main()
    {
        // string inputFile = "../../6_1.csv";           // Tệp cần mã hóa
        // string encryptedFile = "example.enc";       // Tệp đã mã hóa
        // string decryptedFile = "board_contents.csv";   // Tệp sau khi giải mã
        string sourceDirectory = "../../kgon-g";      // Thư mục chứa các tệp cần mã hóa
        string encryptedDirectory = "../../kgon-g-encrypt"; // Thư mục lưu các tệp đã mã hóa
        string decryptedDirectory = "../../kgon-g-decrypt"; // Thư mục lưu các tệp đã giải mã
        byte[] key = GenerateKeyFromPassword("Vpbank@123", 32); // Khóa AES 256-bit (32 byte)
        byte[] iv = GenerateIV();                   // Nonce/IV 12 byte cho GCM

        // Tạo thư mục đích nếu chưa tồn tại
        CreateDirectoryIfNotExists(encryptedDirectory);
        CreateDirectoryIfNotExists(decryptedDirectory);

        // Đo hiệu suất mã hóa
        // MeasurePerformance(() => EncryptFile(inputFile, encryptedFile, key, iv), "Encryption");
        MeasurePerformance(() => EncryptDirectory(sourceDirectory, encryptedDirectory, key, iv), "Encryption");

        // Đo hiệu suất giải mã
        // MeasurePerformance(() => DecryptFile(encryptedFile, decryptedFile, key, iv), "Decryption");
        MeasurePerformance(() => DecryptDirectory(encryptedDirectory, decryptedDirectory, key, iv), "Decryption");
    }

    static void EncryptDirectory(string sourceDir, string destinationDir, byte[] key, byte[] iv)
    {
        string[] files = Directory.GetFiles(sourceDir);

        foreach (string file in files)
        {
            string fileName = Path.GetFileName(file);
            string encryptedFilePath = Path.Combine(destinationDir, fileName + ".enc");

            EncryptFile(file, encryptedFilePath, key, iv);
        }
    }

    static void DecryptDirectory(string sourceDir, string destinationDir, byte[] key, byte[] iv)
    {
        string[] files = Directory.GetFiles(sourceDir, "*.enc");

        foreach (string file in files)
        {
            string fileName = Path.GetFileName(file);
            string decryptedFileName = fileName.Substring(0, fileName.Length - 4); // Bỏ đuôi .enc
            string decryptedFilePath = Path.Combine(destinationDir, decryptedFileName);

            DecryptFile(file, decryptedFilePath, key, iv);
        }
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

    static void MeasurePerformance(Action action, string operation)
    {
        var stopwatch = new Stopwatch();
        stopwatch.Start();

        var process = Process.GetCurrentProcess();
        long initialMemory = GC.GetTotalMemory(true);

        action();

        stopwatch.Stop();
        double elapsedMilliseconds = stopwatch.Elapsed.TotalMilliseconds;

        // Tính toán thời gian CPU sử dụng chia cho số lõi CPU
        double cpuUsage = (process.TotalProcessorTime.TotalMilliseconds / elapsedMilliseconds) / Environment.ProcessorCount * 100;

        long finalMemory = process.WorkingSet64 - initialMemory; // Đo sự thay đổi bộ nhớ hệ thống

        Console.WriteLine($"{operation} completed in {elapsedMilliseconds} ms");
        Console.WriteLine($"{operation} average CPU usage: {cpuUsage:F2}%");
        Console.WriteLine($"{operation} memory used: {finalMemory / (1024 * 1024)} MB");
    }

    static void CreateDirectoryIfNotExists(string directoryPath)
    {
        if (!Directory.Exists(directoryPath))
        {
            Directory.CreateDirectory(directoryPath);
        }
    }
}
