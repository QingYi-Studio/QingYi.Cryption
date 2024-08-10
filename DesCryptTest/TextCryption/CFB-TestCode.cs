using System.Text;

namespace DES.FileCryption
{
    internal class CFBFT
    {
        public static void TCode()
        {
            // Define key and IV (must be 8 bytes for DES)
            byte[] key = Encoding.UTF8.GetBytes("12345678");
            byte[] iv = Encoding.UTF8.GetBytes("87654321");

            // Initialize cipher
            var cipher = new CFB(key, iv);

            // Example string to encrypt
            string originalText = "Hello, DES in CFB mode!";
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(originalText);

            // Encrypt
            byte[] encryptedBytes = cipher.Encrypt(plainTextBytes);
            string encryptedBase64 = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine($"Encrypted (Base64): {encryptedBase64}");

            // Decrypt
            byte[] decryptedBytes = cipher.Decrypt(Convert.FromBase64String(encryptedBase64));
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Decrypted: {decryptedText}");
        }
    }
}
