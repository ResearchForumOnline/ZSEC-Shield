using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserVaultCredential
    {
        public string Id { get; set; }
        public string Url { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Notes { get; set; }
        public string CreatedAtUtc { get; set; }
        public string UpdatedAtUtc { get; set; }
    }

    internal sealed class BrowserVaultCredentialSummary
    {
        public string Id { get; set; }
        public string Url { get; set; }
        public string Username { get; set; }
        public string UpdatedAtUtc { get; set; }
    }

    internal sealed class BrowserPasswordVault : IDisposable
    {
        internal const int MaximumRecords = 5000;
        internal const int MaximumFileBytes = 1024 * 1024;
        internal const string ThreatModel =
            "DPAPI CurrentUser plus an independent random vault master key protects data at rest. " +
            "It does not protect against malware executing as the unlocked Windows user, a stolen " +
            "interactive session, keylogging, page compromise, or browser-process memory access.";

        private const string KeySchema = "zsec.browser.vault-device-key.v1";
        private const string StateSchema = "zsec.browser.password-vault.v1";
        private const string RecordSchema = "zsec.browser.password-record.v1";
        private const int KeyBytes = 32;
        private const int SaltBytes = 32;
        private const int IvBytes = 16;
        private const int MacBytes = 32;
        private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes(
            "ZSEC-BROWSER-VAULT-DPAPI-V1\0TalkToAI"
        );

        private readonly string root;
        private readonly string recordsRoot;
        private readonly string deviceKeyPath;
        private readonly string statePath;
        private readonly JavaScriptSerializer serializer;
        private byte[] masterKey;
        private bool disposed;

        internal BrowserPasswordVault(string productRoot)
        {
            if (String.IsNullOrWhiteSpace(productRoot))
                throw new ArgumentException("A product root is required.", "productRoot");
            string parent = Path.GetFullPath(productRoot);
            root = Path.Combine(parent, "password-vault");
            recordsRoot = Path.Combine(root, "records");
            deviceKeyPath = Path.Combine(root, "device-key.json");
            statePath = Path.Combine(root, "vault-state.json");
            serializer = new JavaScriptSerializer { MaxJsonLength = MaximumFileBytes };
        }

        internal bool IsInitialized { get { return File.Exists(deviceKeyPath) && File.Exists(statePath); } }
        internal bool IsUnlocked { get { return masterKey != null; } }

        internal void Initialize()
        {
            ThrowIfDisposed();
            if (Directory.Exists(root) || File.Exists(root))
                throw new InvalidOperationException("The password vault path already exists; refusing overwrite.");
            CreatePrivateDirectory(root);
            CreatePrivateDirectory(recordsRoot);
            byte[] deviceKey = RandomBytes(KeyBytes);
            byte[] newMaster = RandomBytes(KeyBytes);
            try
            {
                byte[] protectedDevice = ProtectedData.Protect(
                    deviceKey, DpapiEntropy, DataProtectionScope.CurrentUser
                );
                Dictionary<string, object> keyDocument = new Dictionary<string, object>
                {
                    { "schema", KeySchema },
                    { "protection", "Windows DPAPI CurrentUser" },
                    { "protected_key", Convert.ToBase64String(protectedDevice) }
                };
                WriteJsonAtomic(deviceKeyPath, keyDocument, false);

                Dictionary<string, object> wrapped = EncryptEnvelope(
                    newMaster, deviceKey, "ZSEC-BROWSER-VAULT-MASTER-WRAP-V1"
                );
                Dictionary<string, object> state = new Dictionary<string, object>
                {
                    { "schema", StateSchema },
                    { "created_at", UtcNow() },
                    { "key_layers", "DPAPI CurrentUser -> random device key -> random vault master key -> per-record keys" },
                    { "master_key_envelope", wrapped },
                    { "zmath_role", "domain-separated commitment label only; not a cipher or security proof" }
                };
                WriteJsonAtomic(statePath, state, false);
                masterKey = (byte[])newMaster.Clone();
            }
            catch
            {
                DeleteTreeBestEffort(root);
                throw;
            }
            finally
            {
                Zero(deviceKey);
                Zero(newMaster);
            }
        }

        internal void Unlock()
        {
            ThrowIfDisposed();
            if (masterKey != null) return;
            ValidateVaultDirectories();
            Dictionary<string, object> keyDocument = ReadObject(deviceKeyPath, MaximumFileBytes);
            RequireExactKeys(keyDocument, "schema", "protection", "protected_key");
            RequireText(keyDocument, "schema", KeySchema, 80);
            RequireText(keyDocument, "protection", "Windows DPAPI CurrentUser", 80);
            byte[] protectedDevice = DecodeBounded(keyDocument["protected_key"], 16, 4096, "protected device key");
            byte[] deviceKey = null;
            byte[] unwrapped = null;
            try
            {
                deviceKey = ProtectedData.Unprotect(
                    protectedDevice, DpapiEntropy, DataProtectionScope.CurrentUser
                );
                if (deviceKey.Length != KeyBytes) throw new CryptographicException("Device key length is invalid.");
                Dictionary<string, object> state = ReadObject(statePath, MaximumFileBytes);
                RequireExactKeys(state, "schema", "created_at", "key_layers", "master_key_envelope", "zmath_role");
                RequireText(state, "schema", StateSchema, 80);
                Dictionary<string, object> envelope = AsObject(state["master_key_envelope"], "master key envelope");
                unwrapped = DecryptEnvelope(envelope, deviceKey, "ZSEC-BROWSER-VAULT-MASTER-WRAP-V1");
                if (unwrapped.Length != KeyBytes) throw new CryptographicException("Vault master key length is invalid.");
                masterKey = (byte[])unwrapped.Clone();
            }
            finally
            {
                Zero(protectedDevice);
                Zero(deviceKey);
                Zero(unwrapped);
            }
        }

        internal void Lock()
        {
            Zero(masterKey);
            masterKey = null;
        }

        internal string Store(string url, string username, string password)
        {
            return SaveCredential(null, url, username, password, String.Empty).Id;
        }

        internal BrowserVaultCredential SaveCredential(
            string id, string url, string username, string password, string notes
        )
        {
            RequireUnlocked();
            string normalizedUrl = NormalizeUrl(url);
            string normalizedUser = BoundedText(username, "username", 512);
            string normalizedPassword = BoundedText(password, "password", 8192);
            string normalizedNotes = BoundedText(notes ?? String.Empty, "notes", 8192);
            bool creating = String.IsNullOrWhiteSpace(id);
            if (creating && Directory.GetFiles(recordsRoot, "*.json", SearchOption.TopDirectoryOnly).Length >= MaximumRecords)
                throw new InvalidOperationException("Password vault record limit reached.");
            string safeId = creating ? Guid.NewGuid().ToString("N") : ValidateId(id);
            string now = UtcNow();
            string created = now;
            if (!creating) created = Retrieve(safeId).CreatedAtUtc;
            BrowserVaultCredential record = new BrowserVaultCredential
            {
                Id = safeId,
                Url = normalizedUrl,
                Username = normalizedUser,
                Password = normalizedPassword,
                Notes = normalizedNotes,
                CreatedAtUtc = created,
                UpdatedAtUtc = now
            };
            byte[] plaintext = Encoding.UTF8.GetBytes(serializer.Serialize(record));
            try
            {
                Dictionary<string, object> envelope = EncryptEnvelope(
                    plaintext, masterKey, "ZSEC-BROWSER-PASSWORD-RECORD-V1\0" + safeId
                );
                Dictionary<string, object> document = new Dictionary<string, object>
                {
                    { "schema", RecordSchema },
                    { "id", safeId },
                    { "envelope", envelope },
                    { "zmath_commitment", Commitment(safeId, envelope) }
                };
                WriteJsonAtomic(RecordPath(safeId), document, creating);
                return record;
            }
            finally { Zero(plaintext); }
        }

        internal BrowserVaultCredential Retrieve(string id)
        {
            RequireUnlocked();
            string safeId = ValidateId(id);
            Dictionary<string, object> document = ReadObject(RecordPath(safeId), MaximumFileBytes);
            RequireExactKeys(document, "schema", "id", "envelope", "zmath_commitment");
            RequireText(document, "schema", RecordSchema, 80);
            RequireText(document, "id", safeId, 64);
            Dictionary<string, object> envelope = AsObject(document["envelope"], "record envelope");
            string expectedCommitment = Commitment(safeId, envelope);
            RequireText(document, "zmath_commitment", expectedCommitment, 64);
            byte[] plaintext = DecryptEnvelope(
                envelope, masterKey, "ZSEC-BROWSER-PASSWORD-RECORD-V1\0" + safeId
            );
            try
            {
                BrowserVaultCredential credential = serializer.Deserialize<BrowserVaultCredential>(
                    Encoding.UTF8.GetString(plaintext)
                );
                if (credential == null || credential.Id != safeId)
                    throw new InvalidDataException("Password record identity is invalid.");
                credential.Url = NormalizeUrl(credential.Url);
                credential.Username = BoundedText(credential.Username, "username", 512);
                credential.Password = BoundedText(credential.Password, "password", 8192);
                credential.Notes = BoundedText(credential.Notes ?? String.Empty, "notes", 8192);
                return credential;
            }
            finally { Zero(plaintext); }
        }

        internal IList<BrowserVaultCredentialSummary> List()
        {
            RequireUnlocked();
            ValidateVaultDirectories();
            List<BrowserVaultCredentialSummary> result = new List<BrowserVaultCredentialSummary>();
            foreach (string path in Directory.GetFiles(recordsRoot, "*.json", SearchOption.TopDirectoryOnly))
            {
                if (result.Count >= MaximumRecords) throw new InvalidDataException("Password record limit exceeded.");
                BrowserVaultCredential item = Retrieve(Path.GetFileNameWithoutExtension(path));
                result.Add(new BrowserVaultCredentialSummary
                {
                    Id = item.Id,
                    Url = item.Url,
                    Username = item.Username,
                    UpdatedAtUtc = item.UpdatedAtUtc
                });
                item.Password = String.Empty;
            }
            return result.OrderBy(item => item.Url, StringComparer.Ordinal).ThenBy(
                item => item.Username, StringComparer.Ordinal
            ).ToList();
        }

        internal bool Delete(string id)
        {
            RequireUnlocked();
            string path = RecordPath(ValidateId(id));
            if (!File.Exists(path)) return false;
            RejectReparseFile(path);
            File.Delete(path);
            return true;
        }

        internal IList<BrowserVaultCredential> FindForOrigin(string origin)
        {
            string normalized = NormalizeOrigin(origin);
            return List().Where(item => NormalizeOrigin(item.Url) == normalized).Select(
                item => Retrieve(item.Id)
            ).ToList();
        }

        public void Dispose()
        {
            if (disposed) return;
            Lock();
            disposed = true;
        }

        private void RequireUnlocked()
        {
            ThrowIfDisposed();
            if (masterKey == null) throw new InvalidOperationException("Password vault is locked.");
            ValidateVaultDirectories();
        }

        private void ValidateVaultDirectories()
        {
            RejectReparseDirectory(root);
            RejectReparseDirectory(recordsRoot);
        }

        private static Dictionary<string, object> EncryptEnvelope(byte[] plaintext, byte[] rootKey, string context)
        {
            byte[] salt = RandomBytes(SaltBytes);
            byte[] material = HkdfSha256(rootKey, salt, Encoding.UTF8.GetBytes(context), 64);
            byte[] encryptionKey = material.Take(32).ToArray();
            byte[] macKey = material.Skip(32).Take(32).ToArray();
            byte[] iv = RandomBytes(IvBytes);
            byte[] ciphertext;
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = encryptionKey;
                    aes.IV = iv;
                    using (ICryptoTransform transform = aes.CreateEncryptor())
                        ciphertext = transform.TransformFinalBlock(plaintext, 0, plaintext.Length);
                }
                byte[] authenticated = Join(Encoding.UTF8.GetBytes(context), salt, iv, ciphertext);
                byte[] mac;
                using (HMACSHA256 hmac = new HMACSHA256(macKey)) mac = hmac.ComputeHash(authenticated);
                Zero(authenticated);
                return new Dictionary<string, object>
                {
                    { "cipher", "AES-256-CBC-HMAC-SHA256" },
                    { "kdf", "HKDF-SHA256" },
                    { "salt", Convert.ToBase64String(salt) },
                    { "iv", Convert.ToBase64String(iv) },
                    { "ciphertext", Convert.ToBase64String(ciphertext) },
                    { "mac", Convert.ToBase64String(mac) }
                };
            }
            finally
            {
                Zero(salt); Zero(material); Zero(encryptionKey); Zero(macKey); Zero(iv);
            }
        }

        private static byte[] DecryptEnvelope(Dictionary<string, object> envelope, byte[] rootKey, string context)
        {
            RequireExactKeys(envelope, "cipher", "kdf", "salt", "iv", "ciphertext", "mac");
            RequireText(envelope, "cipher", "AES-256-CBC-HMAC-SHA256", 80);
            RequireText(envelope, "kdf", "HKDF-SHA256", 80);
            byte[] salt = DecodeBounded(envelope["salt"], SaltBytes, SaltBytes, "salt");
            byte[] iv = DecodeBounded(envelope["iv"], IvBytes, IvBytes, "IV");
            byte[] ciphertext = DecodeBounded(envelope["ciphertext"], 16, MaximumFileBytes, "ciphertext");
            byte[] mac = DecodeBounded(envelope["mac"], MacBytes, MacBytes, "MAC");
            byte[] material = HkdfSha256(rootKey, salt, Encoding.UTF8.GetBytes(context), 64);
            byte[] encryptionKey = material.Take(32).ToArray();
            byte[] macKey = material.Skip(32).Take(32).ToArray();
            try
            {
                byte[] authenticated = Join(Encoding.UTF8.GetBytes(context), salt, iv, ciphertext);
                byte[] expected;
                using (HMACSHA256 hmac = new HMACSHA256(macKey)) expected = hmac.ComputeHash(authenticated);
                Zero(authenticated);
                if (!FixedTimeEquals(mac, expected))
                {
                    Zero(expected);
                    throw new CryptographicException("Password vault authentication failed.");
                }
                Zero(expected);
                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256; aes.BlockSize = 128; aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7; aes.Key = encryptionKey; aes.IV = iv;
                    using (ICryptoTransform transform = aes.CreateDecryptor())
                        return transform.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
            catch (CryptographicException) { throw; }
            finally
            {
                Zero(salt); Zero(iv); Zero(ciphertext); Zero(mac); Zero(material);
                Zero(encryptionKey); Zero(macKey);
            }
        }

        private static byte[] HkdfSha256(byte[] input, byte[] salt, byte[] info, int length)
        {
            byte[] prk;
            using (HMACSHA256 extract = new HMACSHA256(salt)) prk = extract.ComputeHash(input);
            List<byte> output = new List<byte>(length);
            byte[] previous = new byte[0];
            try
            {
                for (byte counter = 1; output.Count < length; counter++)
                {
                    byte[] blockInput = Join(previous, info, new byte[] { counter });
                    using (HMACSHA256 expand = new HMACSHA256(prk)) previous = expand.ComputeHash(blockInput);
                    Zero(blockInput);
                    output.AddRange(previous);
                }
                return output.Take(length).ToArray();
            }
            finally { Zero(prk); Zero(previous); }
        }

        private static string Commitment(string id, Dictionary<string, object> envelope)
        {
            string projection = id + "\0" + envelope["salt"] + "\0" + envelope["iv"] + "\0" +
                envelope["ciphertext"] + "\0" + envelope["mac"];
            byte[] bytes = Encoding.UTF8.GetBytes("ZSEC-ZMATH-BOUNDARY-COMMITMENT-V1\0" + projection);
            try
            {
                using (SHA256 sha = SHA256.Create())
                    return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
            finally { Zero(bytes); }
        }

        private Dictionary<string, object> ReadObject(string path, int maximum)
        {
            RejectReparseFile(path);
            FileInfo file = new FileInfo(path);
            if (file.Length <= 0 || file.Length > maximum) throw new InvalidDataException("Vault file size is invalid.");
            object value = serializer.DeserializeObject(File.ReadAllText(path, Encoding.UTF8));
            return AsObject(value, "vault document");
        }

        private void WriteJsonAtomic(string path, object value, bool newOnly)
        {
            byte[] bytes = new UTF8Encoding(false).GetBytes(serializer.Serialize(value));
            if (bytes.Length <= 0 || bytes.Length > MaximumFileBytes)
                throw new InvalidDataException("Vault document exceeds its size bound.");
            string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(true);
                }
                HardenFileAcl(temporary);
                if (newOnly && File.Exists(path)) throw new IOException("Vault record already exists.");
                if (File.Exists(path)) File.Replace(temporary, path, null, true);
                else File.Move(temporary, path);
            }
            finally
            {
                Zero(bytes);
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private string RecordPath(string id) { return Path.Combine(recordsRoot, ValidateId(id) + ".json"); }
        private static string ValidateId(string id)
        {
            Guid parsed;
            if (String.IsNullOrWhiteSpace(id) || id.Length != 32 || !Guid.TryParseExact(id, "N", out parsed))
                throw new ArgumentException("Password record ID is invalid.", "id");
            return parsed.ToString("N");
        }

        private static string NormalizeOrigin(string value)
        {
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
                String.IsNullOrWhiteSpace(uri.Host) || !String.IsNullOrEmpty(uri.UserInfo))
                throw new ArgumentException("Credential origin must be an HTTP(S) origin.", "origin");
            UriBuilder builder = new UriBuilder(uri.Scheme, uri.IdnHost, uri.IsDefaultPort ? -1 : uri.Port);
            return builder.Uri.GetLeftPart(UriPartial.Authority).TrimEnd('/').ToLowerInvariant();
        }

        private static string NormalizeUrl(string value)
        {
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
                String.IsNullOrWhiteSpace(uri.Host) || !String.IsNullOrEmpty(uri.UserInfo) ||
                value.Length > 2048)
                throw new ArgumentException("Credential URL must be a bounded HTTP(S) URL.", "url");
            return uri.AbsoluteUri;
        }

        private static string BoundedText(string value, string field, int maximum)
        {
            if (value == null || value.Length > maximum || value.IndexOf('\0') >= 0)
                throw new ArgumentException(field + " is invalid.", field);
            return value;
        }

        private static void RequireExactKeys(Dictionary<string, object> value, params string[] keys)
        {
            if (value == null || value.Count != keys.Length || keys.Any(key => !value.ContainsKey(key)))
                throw new InvalidDataException("Vault document fields are invalid.");
        }

        private static Dictionary<string, object> AsObject(object value, string field)
        {
            Dictionary<string, object> result = value as Dictionary<string, object>;
            if (result == null) throw new InvalidDataException(field + " must be an object.");
            return result;
        }

        private static void RequireText(Dictionary<string, object> value, string key, string expected, int maximum)
        {
            string text = value[key] as string;
            if (text == null || text.Length > maximum || text != expected)
                throw new InvalidDataException("Vault " + key + " is invalid.");
        }

        private static byte[] DecodeBounded(object value, int minimum, int maximum, string field)
        {
            string text = value as string;
            if (String.IsNullOrWhiteSpace(text) || text.Length > (maximum * 2))
                throw new InvalidDataException(field + " is invalid.");
            byte[] result;
            try { result = Convert.FromBase64String(text); }
            catch (FormatException exception) { throw new InvalidDataException(field + " is invalid.", exception); }
            if (result.Length < minimum || result.Length > maximum || Convert.ToBase64String(result) != text)
            {
                Zero(result);
                throw new InvalidDataException(field + " is invalid.");
            }
            return result;
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }

        private static byte[] RandomBytes(int count)
        {
            byte[] result = new byte[count];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(result);
            return result;
        }

        private static byte[] Join(params byte[][] values)
        {
            int length = values.Sum(value => value.Length);
            byte[] result = new byte[length];
            int offset = 0;
            foreach (byte[] value in values)
            {
                Buffer.BlockCopy(value, 0, result, offset, value.Length);
                offset += value.Length;
            }
            return result;
        }

        private static void CreatePrivateDirectory(string path)
        {
            Directory.CreateDirectory(path);
            DirectorySecurity security = new DirectorySecurity();
            SecurityIdentifier owner = WindowsIdentity.GetCurrent().User;
            if (owner == null) throw new InvalidOperationException("Windows user SID is unavailable.");
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(
                owner, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow
            ));
            Directory.SetAccessControl(path, security);
        }

        private static void HardenFileAcl(string path)
        {
            FileSecurity security = new FileSecurity();
            SecurityIdentifier owner = WindowsIdentity.GetCurrent().User;
            if (owner == null) throw new InvalidOperationException("Windows user SID is unavailable.");
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);
        }

        private static void RejectReparseDirectory(string path)
        {
            DirectoryInfo info = new DirectoryInfo(path);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Vault directory is absent or a reparse point.");
        }

        private static void RejectReparseFile(string path)
        {
            FileInfo info = new FileInfo(path);
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Vault file is absent or a reparse point.");
        }

        private static void DeleteTreeBestEffort(string path)
        {
            try { if (Directory.Exists(path)) Directory.Delete(path, true); }
            catch { }
        }

        private static void Zero(byte[] value)
        {
            if (value != null) Array.Clear(value, 0, value.Length);
        }

        private static string UtcNow() { return DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); }
        private void ThrowIfDisposed() { if (disposed) throw new ObjectDisposedException("BrowserPasswordVault"); }
    }

    internal sealed class BrowserVaultService : IVaultService, IDisposable
    {
        private const string Uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        private const string Lowercase = "abcdefghijkmnopqrstuvwxyz";
        private const string Digits = "23456789";
        private const string Symbols = "!@#$%^&*()-_=+[]{}:,.?";
        private readonly BrowserPasswordVault vault;

        internal BrowserVaultService(string productRoot)
        {
            vault = new BrowserPasswordVault(productRoot);
        }

        public BrowserVaultStatus GetStatus()
        {
            int count = 0;
            if (vault.IsUnlocked) count = vault.List().Count;
            return new BrowserVaultStatus
            {
                IsAvailable = true,
                IsUnlocked = vault.IsUnlocked,
                EntryCount = count,
                Message = vault.IsUnlocked
                    ? "Vault unlocked for this Windows session."
                    : "Vault locked; Windows DPAPI is required to unlock it."
            };
        }

        public IList<BrowserVaultEntry> Search(string query)
        {
            string normalized = BrowserVaultUiPolicy.NormalizeSearch(query);
            return vault.List().Select(item => ToEntry(vault.Retrieve(item.Id))).Where(
                item => BrowserVaultUiPolicy.Matches(item, normalized)
            ).ToList();
        }

        public BrowserVaultEntry Get(string id)
        {
            return ToEntry(vault.Retrieve(id));
        }

        public BrowserVaultEntry Save(BrowserVaultEntry entry)
        {
            string error = BrowserVaultUiPolicy.ValidateEntry(entry);
            if (error != null) throw new ArgumentException(error, "entry");
            BrowserVaultCredential saved = vault.SaveCredential(
                entry.Id,
                entry.Url,
                entry.Username ?? String.Empty,
                entry.Password,
                entry.Notes ?? String.Empty
            );
            return ToEntry(saved);
        }

        public void Delete(string id)
        {
            if (!vault.Delete(id)) throw new KeyNotFoundException("Password entry was not found.");
        }

        public void Unlock()
        {
            if (!vault.IsInitialized) vault.Initialize();
            else vault.Unlock();
        }

        public void Lock() { vault.Lock(); }

        public string GeneratePassword(BrowserPasswordGenerationOptions options)
        {
            string error = BrowserVaultUiPolicy.ValidateGenerationOptions(options);
            if (error != null) throw new ArgumentException(error, "options");
            List<string> groups = new List<string>();
            if (options.IncludeUppercase) groups.Add(Uppercase);
            if (options.IncludeLowercase) groups.Add(Lowercase);
            if (options.IncludeDigits) groups.Add(Digits);
            if (options.IncludeSymbols) groups.Add(Symbols);
            string all = String.Concat(groups);
            char[] result = new char[options.Length];
            int position = 0;
            foreach (string group in groups) result[position++] = group[NextInt(group.Length)];
            while (position < result.Length) result[position++] = all[NextInt(all.Length)];
            for (int index = result.Length - 1; index > 0; index--)
            {
                int swap = NextInt(index + 1);
                char temporary = result[index]; result[index] = result[swap]; result[swap] = temporary;
            }
            return new String(result);
        }

        public void Dispose() { vault.Dispose(); }

        private static BrowserVaultEntry ToEntry(BrowserVaultCredential value)
        {
            return new BrowserVaultEntry
            {
                Id = value.Id,
                Url = value.Url,
                Username = value.Username,
                Password = value.Password,
                Notes = value.Notes,
                UpdatedAtUtc = value.UpdatedAtUtc
            };
        }

        private static int NextInt(int upperExclusive)
        {
            if (upperExclusive <= 0) throw new ArgumentOutOfRangeException("upperExclusive");
            ulong range = 1UL << 32;
            ulong limit = range - (range % (uint)upperExclusive);
            byte[] bytes = new byte[4];
            try
            {
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    uint value;
                    do
                    {
                        rng.GetBytes(bytes);
                        value = BitConverter.ToUInt32(bytes, 0);
                    } while ((ulong)value >= limit);
                    return (int)(value % (uint)upperExclusive);
                }
            }
            finally { Array.Clear(bytes, 0, bytes.Length); }
        }
    }
}
