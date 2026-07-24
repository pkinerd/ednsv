using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Xunit;

namespace Ednsv.Web.Tests;

/// <summary>
/// Verifies the data-protection key-ring encryption used when the key-ring lives
/// on a shared RWX mount. The secret is derived via HKDF-SHA256 and the ring
/// elements are sealed with AES-GCM, so this covers key derivation, round-trip,
/// and tamper detection.
/// </summary>
public sealed class DataProtectionSecretTests
{
    private const string ValidSecret = "this-is-a-sufficiently-long-secret!!"; // >= 32 chars

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FromConfig_ReturnsNull_WhenUnset(string? secret)
    {
        Assert.Null(DataProtectionSecret.FromConfig(secret));
    }

    [Fact]
    public void FromConfig_Throws_WhenTooShort()
    {
        var tooShort = new string('x', DataProtectionSecret.MinSecretLength - 1);
        Assert.Throws<ArgumentException>(() => DataProtectionSecret.FromConfig(tooShort));
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        var secret = DataProtectionSecret.FromConfig(ValidSecret)!;
        var encryptor = new SecretXmlEncryptor(secret);
        var decryptor = new SecretXmlDecryptor(secret);

        var plaintext = new XElement("key",
            new XElement("value", "super-secret-key-material"),
            new XAttribute("id", "abc123"));

        EncryptedXmlInfo info = encryptor.Encrypt(plaintext);
        var decrypted = decryptor.Decrypt(info.EncryptedElement);

        Assert.Equal(plaintext.ToString(SaveOptions.DisableFormatting),
                     decrypted.ToString(SaveOptions.DisableFormatting));
    }

    [Fact]
    public void Encrypt_ProducesDifferentCiphertextEachTime()
    {
        var secret = DataProtectionSecret.FromConfig(ValidSecret)!;
        var encryptor = new SecretXmlEncryptor(secret);
        var plaintext = new XElement("key", "same-input");

        var a = encryptor.Encrypt(plaintext).EncryptedElement.Element("value")!.Value;
        var b = encryptor.Encrypt(plaintext).EncryptedElement.Element("value")!.Value;

        // Random per-message nonce => distinct ciphertext even for identical input.
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Decrypt_WithWrongSecret_Fails()
    {
        var enc = new SecretXmlEncryptor(DataProtectionSecret.FromConfig(ValidSecret)!);
        var wrong = new SecretXmlDecryptor(
            DataProtectionSecret.FromConfig("a-completely-different-long-secret!!")!);

        var info = enc.Encrypt(new XElement("key", "value"));

        // AES-GCM authentication tag mismatch under the wrong key.
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => wrong.Decrypt(info.EncryptedElement));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Fails()
    {
        var secret = DataProtectionSecret.FromConfig(ValidSecret)!;
        var info = new SecretXmlEncryptor(secret).Encrypt(new XElement("key", "value"));
        var decryptor = new SecretXmlDecryptor(secret);

        var valueEl = info.EncryptedElement.Element("value")!;
        var blob = Convert.FromBase64String(valueEl.Value);
        blob[^1] ^= 0xFF; // flip a bit in the final ciphertext byte
        valueEl.Value = Convert.ToBase64String(blob);

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => decryptor.Decrypt(info.EncryptedElement));
    }
}
