using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class AesGcmFileEncryption
{
    static void Main(string[] args)
    {
        // string inputFilePath = "../../3.csv";  // Đường dẫn tới file cần mã hoá
        // string encryptedFilePath = "encrypted.enc";  // Đường dẫn tới file mã hoá
        // string decryptedFilePath = "decrypted.csv";  // Đường dẫn tới file giải mã
        string sourceDirectory = "../../kgon-g";      // Thư mục chứa các tệp cần mã hóa
        string encryptedDirectory = "../../kgon-g-encrypt"; // Thư mục lưu các tệp đã mã hóa
        string decryptedDirectory = "../../kgon-g-decrypt"; // Thư mục lưu các tệp đã giải mã
        string keyString = "Vpbank@123";  // Chuỗi để tạo key
        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes(keyString));  // Tạo key từ chuỗi

        // Đo thời gian và tài nguyên khi mã hoá
        Console.WriteLine("Encrypting...");
        // MeasureResourceUsage(() => EncryptFile(inputFilePath, encryptedFilePath, key));
         MeasureResourceUsage(() => EncryptDirectory(sourceDirectory, encryptedDirectory, key));

        // Đo thời gian và tài nguyên khi giải mã
        Console.WriteLine("Decrypting...");
        // MeasureResourceUsage(() => DecryptFile(encryptedFilePath, decryptedFilePath, key));
        MeasureResourceUsage(() => DecryptDirectory(encryptedDirectory, decryptedDirectory, key));
    }

    static void EncryptDirectory(string sourceDir, string destinationDir, byte[] key)
    {
        string[] files = Directory.GetFiles(sourceDir);

        foreach (string file in files)
        {
            string fileName = Path.GetFileName(file);
            string encryptedFilePath = Path.Combine(destinationDir, fileName + ".enc");

            EncryptFile(file, encryptedFilePath, key);
        }
    }

    static void DecryptDirectory(string sourceDir, string destinationDir, byte[] key)
    {
        string[] files = Directory.GetFiles(sourceDir, "*.enc");

        foreach (string file in files)
        {
            string fileName = Path.GetFileName(file);
            string decryptedFileName = fileName.Substring(0, fileName.Length - 4); // Bỏ đuôi .enc
            string decryptedFilePath = Path.Combine(destinationDir, decryptedFileName);

            DecryptFile(file, decryptedFilePath, key);
        }
    }

    static void EncryptFile(string inputFilePath, string outputFilePath, byte[] key)
    {
        byte[] nonce = new byte[12];  // 96-bit nonce cho AES-GCM
        RandomNumberGenerator.Fill(nonce);  // Tạo nonce ngẫu nhiên

        byte[] tag = new byte[16];  // 128-bit tag cho AES-GCM

        using (FileStream inputFile = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
        using (FileStream outputFile = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
        using (AesGcm aesGcm = new AesGcm(key))
        {
            byte[] buffer = new byte[inputFile.Length];
            inputFile.Read(buffer, 0, buffer.Length);

            byte[] encryptedData = new byte[buffer.Length];

            aesGcm.Encrypt(nonce, buffer, encryptedData, tag);

            outputFile.Write(nonce);  // Ghi nonce đầu tiên
            outputFile.Write(tag);    // Ghi tag sau nonce
            outputFile.Write(encryptedData);  // Ghi dữ liệu mã hoá
        }
    }

    static void DecryptFile(string inputFilePath, string outputFilePath, byte[] key)
    {
        using (FileStream inputFile = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
        using (FileStream outputFile = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
        using (AesGcm aesGcm = new AesGcm(key))
        {
            byte[] nonce = new byte[12];
            inputFile.Read(nonce, 0, nonce.Length);

            byte[] tag = new byte[16];
            inputFile.Read(tag, 0, tag.Length);

            byte[] encryptedData = new byte[inputFile.Length - nonce.Length - tag.Length];
            inputFile.Read(encryptedData, 0, encryptedData.Length);

            byte[] decryptedData = new byte[encryptedData.Length];

            aesGcm.Decrypt(nonce, encryptedData, tag, decryptedData);

            outputFile.Write(decryptedData);
        }
    }

    static void MeasureResourceUsage(Action action)
    {
        var stopwatch = new Stopwatch();
        var process = Process.GetCurrentProcess();

        stopwatch.Start();
        action();
        stopwatch.Stop();

        double elapsedMilliseconds = stopwatch.Elapsed.TotalMilliseconds;
        double cpuUsage = (process.TotalProcessorTime.TotalMilliseconds / elapsedMilliseconds) / Environment.ProcessorCount * 100;
        double ramUsage = process.WorkingSet64 / 1024.0 / 1024.0;  // Đổi từ bytes sang MB

        Console.WriteLine($"Time Elapsed: {elapsedMilliseconds} ms");
        Console.WriteLine($"CPU Usage: {cpuUsage:F2}%");
        Console.WriteLine($"RAM Usage: {ramUsage} MB");
    }
}
