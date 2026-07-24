using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
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

    // Regression: DataProtection activates the decryptor named in an encrypted key
    // via its own activator, sometimes WITHOUT the DI container — i.e. through the
    // parameterless constructor. That path previously threw MissingMethodException
    // ("No parameterless constructor defined"), making every encrypted key
    // ineligible and 500-ing SSO. The parameterless ctor must recover the ambient
    // secret and decrypt.
    [Fact]
    public void Decryptor_ParameterlessCtor_RoundTripsViaAmbientSecret()
    {
        var secret = DataProtectionSecret.FromConfig(ValidSecret)!;
        DataProtectionSecret.UseAsAmbient(secret);

        var plaintext = new XElement("masterKey", new XElement("value", "super-secret-key-material"));
        var info = new SecretXmlEncryptor(secret).Encrypt(plaintext);

        // Activator path: no constructor argument, relies on the ambient secret.
        var decrypted = new SecretXmlDecryptor().Decrypt(info.EncryptedElement);

        Assert.Equal("super-secret-key-material", decrypted.Element("value")!.Value);
    }

    // End-to-end through the REAL DataProtection stack: protect with an encrypted
    // key-ring, then read it back in a fresh provider ("restart") whose DI does NOT
    // know DataProtectionSecret — forcing DP to activate SecretXmlDecryptor without
    // the container (the path that 500-ed SSO). The ambient secret must carry it.
    [Fact]
    public void RealDataProtection_UnprotectAfterRestart_UsesAmbientDecryptor()
    {
        var keysDir = Path.Combine(Path.GetTempPath(), $"ednsv-dp-{Guid.NewGuid():N}");
        Directory.CreateDirectory(keysDir);
        try
        {
            var secret = DataProtectionSecret.FromConfig(ValidSecret)!;
            DataProtectionSecret.UseAsAmbient(secret);

            // First process: encrypts the ring and protects a payload. Secret IS in
            // DI here so key generation (which uses the encryptor we set) works.
            string ciphertext;
            using (var sp1 = BuildDpProvider(keysDir, registerSecretInDi: true, secret))
                ciphertext = sp1.GetDataProtector("ednsv-session").Protect("user@example.com");

            // Persisted key is encrypted at rest, not plaintext.
            var keyXml = File.ReadAllText(Directory.EnumerateFiles(keysDir, "key-*.xml").Single());
            Assert.Contains("Encrypted at rest with ednsv", keyXml);
            Assert.DoesNotContain("requiresEncryption=\"true\"", keyXml);

            // "Restart" with the secret absent from DI: DP must fall back to the
            // parameterless decryptor + ambient secret to read the key.
            using (var sp2 = BuildDpProvider(keysDir, registerSecretInDi: false, secret))
                Assert.Equal("user@example.com", sp2.GetDataProtector("ednsv-session").Unprotect(ciphertext));
        }
        finally { Directory.Delete(keysDir, recursive: true); }
    }

    private static ServiceProvider BuildDpProvider(string keysDir, bool registerSecretInDi, DataProtectionSecret secret)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        if (registerSecretInDi) services.AddSingleton(secret);
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(keysDir))
            .SetApplicationName("ednsv");
        services.Configure<KeyManagementOptions>(o => o.XmlEncryptor = new SecretXmlEncryptor(secret));
        return services.BuildServiceProvider();
    }

    // ── Key-ring cleanup (RemoveUnencryptedKeys) ─────────────────────────────

    // DP writes an unencrypted master key with requiresEncryption="true" (as a
    // namespaced attribute); once encrypted the element becomes <encryptedSecret>
    // and the attribute is gone.
    private static string PlaintextKeyXml(string id) => $"""
        <key id="{id}" version="1">
          <creationDate>2026-07-24T00:13:16Z</creationDate>
          <activationDate>2026-07-24T00:13:16Z</activationDate>
          <expirationDate>2026-10-22T00:13:16Z</expirationDate>
          <descriptor deserializerType="Microsoft.AspNetCore.DataProtection.Foo">
            <descriptor>
              <encryption algorithm="AES_256_CBC" />
              <validation algorithm="HMACSHA256" />
              <masterKey p4:requiresEncryption="true" xmlns:p4="http://schemas.asp.net/2015/03/dataProtection">
                <value>bWFzdGVyLWtleS1ieXRlcw==</value>
              </masterKey>
            </descriptor>
          </descriptor>
        </key>
        """;

    private static string EncryptedKeyXml(string id) => $"""
        <key id="{id}" version="1">
          <creationDate>2026-07-24T00:13:16Z</creationDate>
          <activationDate>2026-07-24T00:13:16Z</activationDate>
          <expirationDate>2026-10-22T00:13:16Z</expirationDate>
          <descriptor deserializerType="Microsoft.AspNetCore.DataProtection.Foo">
            <descriptor>
              <encryption algorithm="AES_256_CBC" />
              <validation algorithm="HMACSHA256" />
              <encryptedSecret decryptorType="SecretXmlDecryptor" xmlns="http://schemas.asp.net/2015/03/dataProtection">
                <encryptedKey xmlns="">
                  <value>ZW5jcnlwdGVkLWJsb2I=</value>
                </encryptedKey>
              </encryptedSecret>
            </descriptor>
          </descriptor>
        </key>
        """;

    [Fact]
    public void RemoveUnencryptedKeys_DeletesPlaintextKeepsEncrypted()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"ednsv-keys-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var plain = Path.Combine(dir, "key-11111111-1111-1111-1111-111111111111.xml");
            var enc = Path.Combine(dir, "key-22222222-2222-2222-2222-222222222222.xml");
            File.WriteAllText(plain, PlaintextKeyXml("11111111-1111-1111-1111-111111111111"));
            File.WriteAllText(enc, EncryptedKeyXml("22222222-2222-2222-2222-222222222222"));

            var removed = DataProtectionKeyring.RemoveUnencryptedKeys(dir);

            Assert.Equal(1, removed);
            Assert.False(File.Exists(plain), "plaintext key should be deleted");
            Assert.True(File.Exists(enc), "encrypted key should be kept");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void RemoveUnencryptedKeys_IgnoresNonKeyMalformedAndMissingDir()
    {
        // Missing directory is a no-op.
        Assert.Equal(0, DataProtectionKeyring.RemoveUnencryptedKeys(
            Path.Combine(Path.GetTempPath(), $"ednsv-nope-{Guid.NewGuid():N}")));

        var dir = Path.Combine(Path.GetTempPath(), $"ednsv-keys-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            // Root element isn't <key> — left alone even though it has the attribute.
            var notKey = Path.Combine(dir, "key-33333333-3333-3333-3333-333333333333.xml");
            File.WriteAllText(notKey, "<notAKey requiresEncryption=\"true\"><value>x</value></notAKey>");
            // Malformed XML is skipped, not deleted.
            var malformed = Path.Combine(dir, "key-44444444-4444-4444-4444-444444444444.xml");
            File.WriteAllText(malformed, "not xml at all");

            var removed = DataProtectionKeyring.RemoveUnencryptedKeys(dir);

            Assert.Equal(0, removed);
            Assert.True(File.Exists(notKey));
            Assert.True(File.Exists(malformed));
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
