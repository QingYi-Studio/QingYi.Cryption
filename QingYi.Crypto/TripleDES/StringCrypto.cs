using DES.CBC;
using DES.ECB;
using System;
using System.Text;

namespace TripleDES
{
    /// <summary>
    /// 3DES string crypto. Based on the DES module of this library.<br></br>
    /// 3DES字符串加密。基于本库的DES模块。
    /// </summary>
    public class TripleDesStringCrypto
    {
        private readonly string Key;
        private readonly string IV;

        /// <summary>
        /// constructor<br></br>
        /// 构造函数
        /// </summary>
        /// <param name="key">The encryption key as a string. It should be 8 bytes long for DES.<br></br>加密密钥为字符串。对于DES，它应该是8字节长。</param>
        /// <param name="iv">The initialization vector (IV) as a string. It should be 8 bytes long for DES.<br></br>初始化向量(IV)为字符串。对于DES，它应该是8字节长。</param>
        /// <exception cref="ArgumentException">Thrown when the key or IV is not the correct length (8 bytes).|当key或IV不是正确的长度(8字节)时抛出。</exception>
        public TripleDesStringCrypto(string key, string iv)
        {
            if (key.Length != 24)
                throw new ArgumentException("Key must be 24 bytes long.");
            if (iv.Length != 8)
                throw new ArgumentException("IV must be 8 bytes long.");

            Key = key;
            IV = iv;
        }

        /// <summary>
        /// Cut a 24-byte string into three 8-byte pieces.<br></br>
        /// 将 24 字节的字符串切割成三份，每份 8 字节。
        /// </summary>
        /// <param name="part1">Part1<br></br>第一部分</param>
        /// <param name="part2">Part2<br></br>第二部分</param>
        /// <param name="part3">Part3<br></br>第三部分</param>
        private void GetKey(out string part1, out string part2, out string part3)
        {
            if (Key.Length != 24)
                throw new ArgumentException("Input string must be 24 bytes long.");

            // 将输入字符串转换为字节数组
            byte[] bytes = Encoding.UTF8.GetBytes(Key);

            // 确保字节数组长度为 24
            if (bytes.Length != 24)
                throw new ArgumentException("Input string must be 24 bytes long.");

            // 切割字节数组为三份，每份 8 字节
            part1 = Encoding.UTF8.GetString(bytes, 0, 8);
            part2 = Encoding.UTF8.GetString(bytes, 8, 8);
            part3 = Encoding.UTF8.GetString(bytes, 16, 8);
        }

        /// <summary>
        /// Execute CBC encryption mode.<br></br>
        /// 执行CBC加密模式。
        /// </summary>
        /// <param name="text">Text that needs to be encrypted.<br></br>需要加密的文本。</param>
        /// <returns>Encrypted text<br></br>加密的文本</returns>
        public string CBCEncrypt(string text)
        {
            string originText = text;
            GetKey(out string part1, out string part2, out string part3);
            string encryptText1 = DesCbcTextCrypto.Encrypt(originText, part1, IV);
            string encryptText2 = DesCbcTextCrypto.Encrypt(encryptText1, part2, IV);
            string encryptText3 = DesCbcTextCrypto.Encrypt(encryptText2, part3, IV);
            return encryptText3;
        }

        /// <summary>
        /// Execute CBC decryption mode.<br></br>
        /// 执行CBC解密模式。
        /// </summary>
        /// <param name="text">Text that needs to be decrypted.<br></br>需要解密的文本。</param>
        /// <returns>Decrypted text<br></br>解密的文本</returns>
        public string CBCDecrypt(string text)
        {
            string encryptText = text;
            GetKey(out string part1, out string part2, out string part3);
            string decryptText1 = DesCbcTextCrypto.Decrypt(encryptText, part3, IV);
            string decryptText2 = DesCbcTextCrypto.Decrypt(decryptText1, part2, IV);
            string decryptText3 = DesCbcTextCrypto.Decrypt(decryptText2, part1, IV);
            return decryptText3;
        }

        /// <summary>
        /// Execute ECB encryption mode.<br></br>
        /// 执行ECB加密模式。
        /// </summary>
        /// <param name="text">Text that needs to be encrypted.<br></br>需要加密的文本。</param>
        /// <returns>Encrypted text<br></br>加密的文本</returns>
        public string ECBEncrypt(string text)
        {
            GetKey(out string part1, out string part2, out string part3);
            DesEcbTextCrypto ecb1 = new DesEcbTextCrypto(part1);
            DesEcbTextCrypto ecb2 = new DesEcbTextCrypto(part2);
            DesEcbTextCrypto ecb3 = new DesEcbTextCrypto(part3);
            string originText = text;
            string encryptText1 = ecb1.EncryptString(text);
            string encryptText2 = ecb2.EncryptString(encryptText1);
            string encryptText3 = ecb3.EncryptString(encryptText2);
            return encryptText3;
        }

        /// <summary>
        /// Execute ECB decryption mode.<br></br>
        /// 执行ECB解密模式。
        /// </summary>
        /// <param name="text">Text that needs to be decrypted.<br></br>需要解密的文本。</param>
        /// <returns>Decrypted text<br></br>解密的文本</returns>
        public string ECBDecrypt(string text)
        {
            GetKey(out string part1, out string part2, out string part3);
            DesEcbTextCrypto ecb1 = new DesEcbTextCrypto(part1);
            DesEcbTextCrypto ecb2 = new DesEcbTextCrypto(part2);
            DesEcbTextCrypto ecb3 = new DesEcbTextCrypto(part3);
            string encryptText = text;
            string decryptText1 = ecb3.DecryptString(encryptText);
            string decryptText2 = ecb2.DecryptString(decryptText1);
            string decryptText3 = ecb1.DecryptString(decryptText2);
            return decryptText3;
        }
    }
}
