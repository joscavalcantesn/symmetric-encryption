using System.Security.Cryptography;
using System.Text;

var plainText = "Hello, World!";

// Use a more secure approach for key derivation
var password = "MySecurePassword123!";
var salt = RandomNumberGenerator.GetBytes(16); // Store this with encrypted data
var masterKey = DeriveKey(password, salt);

var encrypted = Encrypt(plainText, masterKey);
Console.WriteLine($"Texto criptografado: {encrypted}");

var decrypted = Decrypt(encrypted, masterKey);
Console.WriteLine($"Texto descriptografado: {decrypted}");
Console.WriteLine($"Verificação: {plainText == decrypted}");

//Clear sensitive data from memory
Array.Clear(masterKey);

const int IvSize = 16;
const int KeySize = 32;

static byte[] DeriveKey(string password, ReadOnlySpan<byte> salt)
{
    using var pbkdf2 = new Rfc2898DeriveBytes(password, salt.ToArray(), 100000, HashAlgorithmName.SHA256);
    return pbkdf2.GetBytes(KeySize);
}

static string Encrypt(string plainText, ReadOnlySpan<byte> masterKey)
{
    if (string.IsNullOrEmpty(plainText))
        throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));

    var plainBytes = Encoding.UTF8.GetBytes(plainText);

    using var aes = Aes.Create();
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;
    aes.Key = masterKey.ToArray();

    var iv = RandomNumberGenerator.GetBytes(IvSize);
    aes.IV = iv;

    using var memoryStream = new MemoryStream();

    // Write IV to the beginning of the stream
    memoryStream.Write(iv);

    // Encrypt the data
    using (var encryptor = aes.CreateEncryptor())
    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
    {
        cryptoStream.Write(plainBytes);
        cryptoStream.FlushFinalBlock();
    }

    var result = Convert.ToBase64String(memoryStream.ToArray());

    // Clear sensitive data
    Array.Clear(plainBytes);
    Array.Clear(iv);

    return result;
}

static string Decrypt(string cipherText, ReadOnlySpan<byte> masterKey)
{
    if (string.IsNullOrEmpty(cipherText))
        throw new ArgumentException("Cipher text cannot be null or empty.", nameof(cipherText));

    try
    {
        var cipherData = Convert.FromBase64String(cipherText);

        if (cipherData.Length < IvSize)
            throw new ArgumentException("Dados criptografados inválidos: muito pequenos.");

        var cipherSpan = cipherData.AsSpan();
        var iv = cipherSpan[..IvSize];
        var encryptedData = cipherSpan[IvSize..];

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = masterKey.ToArray();
        aes.IV = iv.ToArray();

        using var memoryStream = new MemoryStream(encryptedData.ToArray());
        using var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

        // Pre-allocate buffer to avoid multiple allocations
        var buffer = new byte[encryptedData.Length];
        var totalBytesRead = 0;
        int bytesRead;

        while ((bytesRead = cryptoStream.Read(buffer.AsSpan(totalBytesRead))) > 0)
        {
            totalBytesRead += bytesRead;
        }

        var result = Encoding.UTF8.GetString(buffer, 0, totalBytesRead);

        // Clear sensitive data
        Array.Clear(buffer);
        Array.Clear(cipherData);

        return result;
    }
    catch (CryptographicException ex)
    {
        throw new InvalidOperationException("Falha na descriptografia: dados corrompidos ou chave incorreta.", ex);
    }
    catch (FormatException ex)
    {
        throw new ArgumentException("Formato de dados criptografados inválido.", ex);
    }
}