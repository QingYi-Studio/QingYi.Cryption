using CryptTest_TripleDes;

TDesString desString = new TDesString("123456781234567812345678", "12345678");
string encrypt = desString.CBCEncrypt("HaHaHa");
string decrypt = desString.CBCDecrypt(encrypt);

Console.WriteLine(encrypt);
Console.WriteLine(decrypt);