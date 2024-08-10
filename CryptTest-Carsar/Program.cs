using Caesar;

Console.Write("请输入要加密的字符串: ");
string input = Console.ReadLine()!;

Console.Write("请输入移位数: ");
int shift = int.Parse(Console.ReadLine()!);

// 对输入字符串进行凯撒加密
string encrypted = CaesarCipher.Encrypt(input, shift);
Console.WriteLine("加密后的字符串: " + encrypted);

// 对加密后的字符串进行凯撒解密
string decrypted = CaesarCipher.Decrypt(encrypted, shift);
Console.WriteLine("解密后的字符串: " + decrypted);