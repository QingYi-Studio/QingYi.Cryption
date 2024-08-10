using System.Text;

namespace Caesar
{
    public class CaesarCipher
    {
        public static string Encrypt(string text, int shift)
        {
            return CaesarEncrypt(text, shift);
        }

        public static string Decrypt(string text, int shift)
        {
            return CaesarDecrypt(text, shift);
        }

        private static string CaesarEncrypt(string text, int shift)
        {
            StringBuilder result = new StringBuilder();
            foreach (char c in text)
            {
                char encryptedChar = (char)(c + shift);
                result.Append(encryptedChar);
            }
            return result.ToString();
        }

        private static string CaesarDecrypt(string text, int shift)
        {
            StringBuilder result = new StringBuilder();
            foreach (char c in text)
            {
                char decryptedChar = (char)(c - shift);
                result.Append(decryptedChar);
            }
            return result.ToString();
        }
    }
}
