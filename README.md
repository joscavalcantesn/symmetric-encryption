# 🔐 Symmetric Encryption - AES em C#

Exemplo prático de **criptografia simétrica** usando **AES** em **C#**.  
Este repositório demonstra como criptografar e descriptografar textos de forma segura utilizando **AES em modo CBC com padding PKCS7**.

---

## ⚙️ Funcionalidades
- Geração de **chave aleatória** (32 bytes)  
- Criptografia de texto em **Base64**  
- Descriptografia de texto criptografado  
- Validação básica de integridade dos dados  

---

## 📋 Pré-requisitos
- .NET 8

---

## ▶️ Exemplo de uso
```csharp
var plainText = "Hello, World!";
var masterKey = RandomNumberGenerator.GetBytes(32);

var encrypted = Encrypt(plainText, masterKey);
Console.WriteLine($"Texto criptografado: {encrypted}");

var decrypted = Decrypt(encrypted, masterKey);
Console.WriteLine($"Texto descriptografado: {decrypted}");
Console.WriteLine(plainText == decrypted);
