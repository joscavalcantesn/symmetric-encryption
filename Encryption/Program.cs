using System.Security.Cryptography;

var plainText = "Hello, World!";

var masterKey = RandomNumberGenerator.GetBytes(32);

var encrypted = Encrypt(plainText, masterKey);

Console.WriteLine($"Texto criptografado: {encrypted}");

var decrypted = Decrypt(encrypted, masterKey);

Console.WriteLine($"Texto descriptografado: {decrypted}");

Console.WriteLine(plainText == decrypted);

const int ivSize = 16;

static string Encrypt(string plainText, byte[] masterKey)
{
    using var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;
    aes.Key = masterKey;
    aes.IV = RandomNumberGenerator.GetBytes(ivSize);

    using var memoryStream = new MemoryStream();
    memoryStream.Write(aes.IV, 0, ivSize);

    using (var encryptor = aes.CreateEncryptor())
    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
    using (var streamWriter = new StreamWriter(cryptoStream))
    {
        streamWriter.Write(plainText);
    }

    return Convert.ToBase64String(memoryStream.ToArray());
}

static string Decrypt(string cipherText, byte[] masterKey)
{
    try
    {
        byte[] cipherData = Convert.FromBase64String(cipherText);

        if (cipherData.Length < ivSize)
        {
            throw new InvalidOperationException("Dados criptografados inválidos.");
        }

        byte[] iv = new byte[ivSize];
        byte[] encryptedData = new byte[cipherData.Length - ivSize];

        Buffer.BlockCopy(cipherData, 0, iv, 0, ivSize);
        Buffer.BlockCopy(cipherData, ivSize, encryptedData, 0, encryptedData.Length);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = masterKey;
        aes.IV = iv;

        using var memoryStream = new MemoryStream(encryptedData);
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        using var streamReader = new StreamReader(cryptoStream);

        return streamReader.ReadToEnd();
    }
    catch (CryptographicException ex)
    {

        throw new InvalidOperationException("Falha na descriptografia", ex);
    }
}