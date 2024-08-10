using System.Text;

namespace DES.TextCryption
{
    internal class CFBTT
    {
        public static void TCode()
        {
            // Define key and IV (must be 8 bytes for DES)
            byte[] key = Encoding.UTF8.GetBytes("12345678");
            byte[] iv = Encoding.UTF8.GetBytes("87654321");

            // Initialize cipher
            var cipher = new CFB(key, iv);

            // Paths to input and output files
            string inputFilePath = "test.txt";
            string encryptedFilePath = "encryptedfile.des-encrypt";
            string decryptedFilePath = "decryptedfile.txt";

            // Encrypt the file
            cipher.EncryptFile(inputFilePath, encryptedFilePath);
            Console.WriteLine("File encrypted successfully.");

            // Decrypt the file
            cipher.DecryptFile(encryptedFilePath, decryptedFilePath);
            Console.WriteLine("File decrypted successfully.");
        }
    }
}
