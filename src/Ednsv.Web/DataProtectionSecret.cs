using System.Globalization;
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

    // Ambient secret used by the DataProtection-activated decryptor. DP constructs
    // the IXmlDecryptor named in each encrypted key via its own activator, which in
    // some hosting paths runs WITHOUT the DI container (it calls the parameterless
    // constructor). The ambient instance lets that path recover the key without
    // constructor injection. Set once at startup when the secret is configured.
    private static DataProtectionSecret? _ambient;

    /// <summary>The process-wide secret for the DP-activated decryptor, or null when unset.</summary>
    public static DataProtectionSecret? Ambient => _ambient;

    /// <summary>Registers <paramref name="secret"/> as the ambient decryptor secret.</summary>
    public static void UseAsAmbient(DataProtectionSecret secret) =>
        _ambient = secret ?? throw new ArgumentNullException(nameof(secret));

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

    /// <summary>
    /// Parameterless constructor for the DataProtection activator, which
    /// instantiates the decryptor named in each encrypted key and may do so
    /// without the DI container. Falls back to the ambient secret configured at
    /// startup; throws a clear error if none is set (e.g. the encrypted key-ring
    /// is present but DataProtection:KeyEncryptionSecret is missing).
    /// </summary>
    public SecretXmlDecryptor()
        : this(DataProtectionSecret.Ambient ?? throw new InvalidOperationException(
            "The data-protection key-ring is encrypted but no DataProtection:KeyEncryptionSecret "
            + "is configured, so it cannot be decrypted. Set the same secret used to encrypt it."))
    { }

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

/// <summary>
/// Startup maintenance for the data-protection key-ring on disk.
/// </summary>
public static class DataProtectionKeyring
{
    /// <summary>
    /// When a key-encryption secret is configured, delete any key-ring files that
    /// are still stored unencrypted so the next key request writes a fresh,
    /// encrypted key. ASP.NET Data Protection applies the <c>XmlEncryptor</c> only
    /// to newly generated keys — it never re-encrypts an existing plaintext key —
    /// so without this a plaintext key would persist on the (shared) mount until it
    /// expires. Preserving keys is intentionally sacrificed: dropping them only
    /// invalidates active OIDC session cookies (users re-authenticate); the token
    /// cookie is not data-protected.
    /// </summary>
    /// <returns>The number of unencrypted key files removed.</returns>
    public static int RemoveUnencryptedKeys(string keysPath, Action<string>? warn = null)
    {
        DirectoryInfo dir;
        try
        {
            dir = new DirectoryInfo(keysPath);
            if (!dir.Exists) return 0;
        }
        catch
        {
            return 0;
        }

        var removed = 0;
        foreach (var file in dir.EnumerateFiles("key-*.xml"))
        {
            bool unencrypted;
            try { unencrypted = IsUnencryptedKeyFile(file.FullName); }
            catch { continue; } // unreadable/not XML — leave it for DP to deal with
            if (!unencrypted) continue;
            try
            {
                file.Delete();
                removed++;
            }
            catch (Exception ex)
            {
                warn?.Invoke($"Could not remove unencrypted data-protection key file {file.Name}: {ex.Message}");
            }
        }
        return removed;
    }

    /// <summary>
    /// True when the file is a data-protection key stored in plaintext. DP marks
    /// the master-key element <c>requiresEncryption="true"</c> only while it is
    /// still unencrypted; once encrypted that element is replaced by an
    /// &lt;encryptedSecret&gt; wrapper and the attribute is gone.
    /// </summary>
    private static bool IsUnencryptedKeyFile(string path)
    {
        var root = XDocument.Load(path).Root;
        if (root == null || !string.Equals(root.Name.LocalName, "key", StringComparison.Ordinal))
            return false; // not a key-ring key file — don't touch it

        foreach (var el in root.Descendants())
            foreach (var attr in el.Attributes())
                if (string.Equals(attr.Name.LocalName, "requiresEncryption", StringComparison.Ordinal)
                    && string.Equals(attr.Value, "true", StringComparison.OrdinalIgnoreCase))
                    return true;
        return false;
    }

    /// <summary>
    /// Deletes key-ring files whose expiration is further in the past than
    /// <paramref name="retention"/>. DataProtection never removes expired keys
    /// itself, so on a long-lived (shared) mount they accumulate. A key can still be
    /// needed to unprotect a payload until that payload's own lifetime elapses, so
    /// the caller must pass a retention window comfortably larger than the longest
    /// protected-payload lifetime (here the OIDC session cookie). Keys that expire
    /// in the future (including the active key), expire within the retention window,
    /// or have no parseable expiration are always kept. Run before the provider
    /// reads the ring so DP never references a removed key.
    /// </summary>
    /// <returns>The number of expired key files removed.</returns>
    public static int RemoveStaleKeys(string keysPath, TimeSpan retention, Action<string>? warn = null)
    {
        DirectoryInfo dir;
        try
        {
            dir = new DirectoryInfo(keysPath);
            if (!dir.Exists) return 0;
        }
        catch
        {
            return 0;
        }

        var cutoff = DateTimeOffset.UtcNow - retention;
        var removed = 0;
        foreach (var file in dir.EnumerateFiles("key-*.xml"))
        {
            DateTimeOffset? expiry;
            try { expiry = ReadKeyExpiration(file.FullName); }
            catch { continue; } // unreadable/not a key — leave it
            // Keep: no expiry, still valid, or expired but within the retention window.
            if (expiry == null || expiry.Value >= cutoff) continue;
            try
            {
                file.Delete();
                removed++;
            }
            catch (Exception ex)
            {
                warn?.Invoke($"Could not remove expired data-protection key file {file.Name}: {ex.Message}");
            }
        }
        return removed;
    }

    /// <summary>Reads a key file's &lt;expirationDate&gt;, or null when the file is
    /// not a key-ring key or has no parseable expiration.</summary>
    private static DateTimeOffset? ReadKeyExpiration(string path)
    {
        var root = XDocument.Load(path).Root;
        if (root == null || !string.Equals(root.Name.LocalName, "key", StringComparison.Ordinal))
            return null;

        foreach (var el in root.Elements())
        {
            if (!string.Equals(el.Name.LocalName, "expirationDate", StringComparison.Ordinal)) continue;
            return DateTimeOffset.TryParse(el.Value, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var dto)
                ? dto : null;
        }
        return null;
    }
}
