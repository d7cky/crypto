using System;
using System.IO; // Để làm việc với file
using System.Text; // Để sử dụng Encoding.UTF8
using Sodium;
using System.Diagnostics;

class Program
{
    static void Main(string[] args)
    {
        // Đường dẫn file đầu vào và đầu ra
        // string inputFilePath = "../../5_1.csv"; // Thay đổi đường dẫn file phù hợp
        // string encryptedFilePath = "encrypt.enc";
        // string decryptedFilePath = "decrypt.csv";
        string sourceDirectory = "../../kgon-g";      // Thư mục chứa các tệp cần mã hóa
        string encryptedDirectory = "../../kgon-g-encrypt"; // Thư mục lưu các tệp đã mã hóa
        string decryptedDirectory = "../../kgon-g-decrypt"; // Thư mục lưu các tệp đã giải mã
        // Khóa bí mật dưới dạng chuỗi
        string keyString = "Vpbank@123";

        // Chuyển đổi khóa chuỗi thành mảng byte (32 byte cho AES-256)
        byte[] key = GenerateKeyFromString(keyString);

        // Tạo nonce (số ngẫu nhiên duy nhất)
        byte[] nonce = SecretBox.GenerateNonce();

        // Đo hiệu suất mã hóa
        // MeasurePerformance(() => EncryptFile(inputFilePath, encryptedFilePath, nonce, key), "Encryption");
        MeasurePerformance(() => EncryptDirectory(sourceDirectory, encryptedDirectory, nonce, key), "Encryption");

        // Đo hiệu suất giải mã
        // MeasurePerformance(() => DecryptFile(encryptedFilePath, decryptedFilePath, nonce, key), "Decryption");
        MeasurePerformance(() => DecryptDirectory(encryptedDirectory, decryptedDirectory, nonce, key), "Decryption");

        // // Mã hóa file
        // EncryptFile(inputFilePath, encryptedFilePath, nonce, key);
        // Console.WriteLine($"File đã được mã hóa: {encryptedFilePath}");

        // // Giải mã file
        // DecryptFile(encryptedFilePath, decryptedFilePath, nonce, key);
        // Console.WriteLine($"File đã được giải mã: {decryptedFilePath}");
    }

    static void EncryptDirectory(string sourceDir, string destinationDir, byte[] nonce, byte[] key)
    {
        string[] files = Directory.GetFiles(sourceDir);

        foreach (string file in files)
        {
            string fileName = Path.GetFileName(file);
            string encryptedFilePath = Path.Combine(destinationDir, fileName + ".enc");

            EncryptFile(file, encryptedFilePath, nonce, key);
        }
    }

    static void DecryptDirectory(string sourceDir, string destinationDir, byte[] nonce, byte[] key)
    {
        string[] files = Directory.GetFiles(sourceDir, "*.enc");

        foreach (string file in files)
        {
            string fileName = Path.GetFileName(file);
            string decryptedFileName = fileName.Substring(0, fileName.Length - 4); // Bỏ đuôi .enc
            string decryptedFilePath = Path.Combine(destinationDir, decryptedFileName);

            DecryptFile(file, decryptedFilePath, nonce, key);
        }
    }

    // Hàm chuyển đổi chuỗi thành mảng byte cho khóa
    static byte[] GenerateKeyFromString(string keyString)
    {
        // Hash chuỗi để đảm bảo chiều dài khóa là 32 byte cho AES-256
        return GenericHash.Hash(Encoding.UTF8.GetBytes(keyString), null, 32);
    }

    // Hàm mã hóa file
    static void EncryptFile(string inputFilePath, string outputFilePath, byte[] nonce, byte[] key)
    {
        // Đọc nội dung file thành mảng byte
        byte[] fileContent = File.ReadAllBytes(inputFilePath);

        // Mã hóa nội dung file
        byte[] encryptedContent = SecretBox.Create(fileContent, nonce, key);

        // Ghi nội dung đã mã hóa ra file
        File.WriteAllBytes(outputFilePath, encryptedContent);
    }

    // Hàm giải mã file
    static void DecryptFile(string inputFilePath, string outputFilePath, byte[] nonce, byte[] key)
    {
        // Đọc nội dung file mã hóa thành mảng byte
        byte[] encryptedContent = File.ReadAllBytes(inputFilePath);

        // Giải mã nội dung file
        byte[] decryptedContent = SecretBox.Open(encryptedContent, nonce, key);

        // Ghi nội dung đã giải mã ra file
        File.WriteAllBytes(outputFilePath, decryptedContent);
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
}
