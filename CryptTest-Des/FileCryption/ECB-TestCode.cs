using System.Text;

namespace DES.FileCryption
{
    public class ECBFT
    {
        public static void TCode()
        {
            string inputFilePath = "test.txt";  // 输入文件路径
            string encryptedFilePath = "encrypted.bin";  // 加密后的文件路径
            string decryptedFilePath = "decrypted.txt";  // 解密后的文件路径

            byte[] key = Encoding.UTF8.GetBytes("12345678"); // DES key must be 8 bytes long

            // 创建 DesFileEncryption 实例
            ECB desFileEncryption = new ECB(key);

            // 加密文件
            desFileEncryption.Encrypt(inputFilePath, encryptedFilePath);
            Console.WriteLine("File encrypted successfully.");

            // 解密文件
            desFileEncryption.Decrypt(encryptedFilePath, decryptedFilePath);
            Console.WriteLine("File decrypted successfully.");
        }
    }
}
