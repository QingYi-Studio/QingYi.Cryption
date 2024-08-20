using CryptTest_MD5;

Console.WriteLine(MD5String.ComputeMD5Base64("123456"));
Console.ReadLine();

string filePath = "test.txt";

string base64Hash = MD5File.ComputeFileMD5Base64(filePath);
Console.WriteLine("File MD5 Base64: " + base64Hash);

string hexHash = MD5File.ComputeFileMD5Hex(filePath);
Console.WriteLine("File MD5 Hex: " + hexHash);
