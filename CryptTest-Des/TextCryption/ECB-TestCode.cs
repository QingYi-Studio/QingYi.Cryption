namespace DES.TextCryption
{
    public class ECBTT
    {
        public static void TCode()
        {
            string originalText = "Hello, World!";
            string key = "12345678";

            // 创建 DesEncryption 实例
            ECB desEncryption = new ECB(key);

            // 加密
            byte[] encrypted = desEncryption.Encrypt(originalText);
            Console.WriteLine("Encrypted (Base64): " + Convert.ToBase64String(encrypted));

            // 解密
            string decrypted = desEncryption.Decrypt(encrypted);
            Console.WriteLine("Decrypted: " + decrypted);
        }
    }
}
