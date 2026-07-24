using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

/// <summary>
/// Derives a 256-bit symmetric key from an operator-supplied secret and uses it
/// to encrypt the ASP.NET Core data-protection key-ring at rest with AES-GCM.
///
/// The key-ring lives on the shared RWX file mount so all pods share one ring
/// (required for OIDC session cookies to validate across replicas). Because the
/// mount may be readable by more than the app, the ring can be encrypted with a
/// secret injected via <c>DataProtection:KeyEncryptionSecret</c>.
///
/// The secret is treated as opaque UTF-8 — no hex/base64 requirement — and must
/// be at least <see cref="MinSecretLength"/> characters. The raw bytes are run
/// through HKDF-SHA256 to derive the AES key.
/// </summary>
public sealed class DataProtectionSecret
{
    /// <summary>Minimum secret length (characters). ~128 bits at a conservative
    /// entropy estimate; a random string does far better.</summary>
    public const int MinSecretLength = 32;

    private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("ednsv-dataprotection-keyring-v1");

    private readonly byte[] _key; // 32 bytes

    private DataProtectionSecret(byte[] key) => _key = key;

    /// <summary>
    /// Builds the derived key from the configured secret, or returns null when no
    /// secret is configured (key-ring is then written unencrypted).
    /// Throws <see cref="ArgumentException"/> when the secret is too short.
    /// </summary>
    public static DataProtectionSecret? FromConfig(string? secret)
    {
        if (string.IsNullOrEmpty(secret)) return null;
        if (secret.Length < MinSecretLength)
            throw new ArgumentException(
                $"DataProtection:KeyEncryptionSecret must be at least {MinSecretLength} characters.");

        var ikm = Encoding.UTF8.GetBytes(secret);
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, outputLength: 32, salt: null, info: HkdfInfo);
        return new DataProtectionSecret(key);
    }

    internal byte[] KeyCopy() => (byte[])_key.Clone();
}

/// <summary>Encrypts data-protection XML elements with AES-GCM using the derived key.</summary>
public sealed class SecretXmlEncryptor : IXmlEncryptor
{
    private readonly DataProtectionSecret _secret;
    public SecretXmlEncryptor(DataProtectionSecret secret) => _secret = secret;

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);

        var plaintext = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        var key = _secret.KeyCopy();
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            var ciphertext = new byte[plaintext.Length];

            using (var gcm = new AesGcm(key, tag.Length))
                gcm.Encrypt(nonce, plaintext, ciphertext, tag);

            // Layout: nonce || tag || ciphertext, base64-encoded.
            var blob = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, blob, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, blob, nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, blob, nonce.Length + tag.Length, ciphertext.Length);

            var encryptedElement = new XElement("encryptedKey",
                new XComment(" Encrypted at rest with ednsv DataProtection:KeyEncryptionSecret (AES-GCM). "),
                new XElement("value", Convert.ToBase64String(blob)));

            return new EncryptedXmlInfo(encryptedElement, typeof(SecretXmlDecryptor));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}

/// <summary>Decrypts elements produced by <see cref="SecretXmlEncryptor"/>. Activated via DI.</summary>
public sealed class SecretXmlDecryptor : IXmlDecryptor
{
    private readonly DataProtectionSecret _secret;
    public SecretXmlDecryptor(DataProtectionSecret secret) => _secret = secret;

    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);

        var value = encryptedElement.Element("value")?.Value
            ?? throw new InvalidOperationException("Malformed encrypted data-protection element: missing <value>.");
        var blob = Convert.FromBase64String(value);

        int nonceLen = AesGcm.NonceByteSizes.MaxSize;
        int tagLen = AesGcm.TagByteSizes.MaxSize;
        if (blob.Length < nonceLen + tagLen)
            throw new InvalidOperationException("Malformed encrypted data-protection element: blob too short.");

        var nonce = new byte[nonceLen];
        var tag = new byte[tagLen];
        var ciphertext = new byte[blob.Length - nonceLen - tagLen];
        Buffer.BlockCopy(blob, 0, nonce, 0, nonceLen);
        Buffer.BlockCopy(blob, nonceLen, tag, 0, tagLen);
        Buffer.BlockCopy(blob, nonceLen + tagLen, ciphertext, 0, ciphertext.Length);

        var plaintext = new byte[ciphertext.Length];
        var key = _secret.KeyCopy();
        try
        {
            using var gcm = new AesGcm(key, tag.Length);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext);
            return XElement.Parse(Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
