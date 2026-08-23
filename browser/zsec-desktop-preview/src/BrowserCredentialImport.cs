using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserCredentialImportPlan
    {
        public string SourceFormat { get; set; }
        public int DataRows { get; set; }
        public int InvalidRows { get; set; }
        public int DuplicateRows { get; set; }
        public IList<BrowserVaultEntry> Candidates { get; set; }
        public long SourceLength { get; set; }
        public string SourceSha256 { get; set; }
    }

    internal sealed class BrowserCredentialImportResult
    {
        public int Imported { get; set; }
        public int ExistingSkipped { get; set; }
    }

    internal static class BrowserCredentialImportPolicy
    {
        internal const int MaximumFileBytes = 2 * 1024 * 1024;
        internal const int MaximumRows = 1000;
        internal const int MaximumColumns = 12;

        private static readonly string[] ChromiumHeaders =
            { "name", "url", "username", "password", "note" };
        private static readonly string[] ChromiumHeadersWithoutNote =
            { "name", "url", "username", "password" };
        private static readonly string[] FirefoxHeaders =
        {
            "url", "username", "password", "httprealm", "formactionorigin", "guid",
            "timecreated", "timelastused", "timepasswordchanged"
        };

        internal static BrowserCredentialImportPlan ParseExport(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) throw new ArgumentException("Choose a CSV export.", "path");
            string full = Path.GetFullPath(path);
            FileInfo file = new FileInfo(full);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The credential export must be a regular file.");
            if (!String.Equals(file.Extension, ".csv", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The credential export must be a .csv file.");
            if (file.Length <= 0 || file.Length > MaximumFileBytes)
                throw new InvalidDataException("The credential export size is outside policy.");
            byte[] raw = File.ReadAllBytes(full);
            string text;
            try { text = new UTF8Encoding(false, true).GetString(raw); }
            catch (DecoderFallbackException exception)
            { throw new InvalidDataException("The credential export must be strict UTF-8.", exception); }
            if (text.IndexOf('\0') >= 0) throw new InvalidDataException("The credential export contains a null character.");
            IList<IList<string>> rows = ParseCsv(text);
            if (rows.Count < 2) throw new InvalidDataException("The credential export has no data rows.");
            IList<string> header = rows[0].Select(value => (value ?? String.Empty).Trim().ToLowerInvariant()).ToList();
            string format;
            if (header.SequenceEqual(ChromiumHeaders) || header.SequenceEqual(ChromiumHeadersWithoutNote))
                format = "Chrome, Edge or Brave password CSV";
            else if (header.SequenceEqual(FirefoxHeaders)) format = "Firefox password CSV";
            else throw new InvalidDataException("CSV headers are not an accepted browser password export.");
            int urlIndex = header.IndexOf("url");
            int usernameIndex = header.IndexOf("username");
            int passwordIndex = header.IndexOf("password");
            int noteIndex = header.IndexOf("note");
            List<BrowserVaultEntry> candidates = new List<BrowserVaultEntry>();
            HashSet<string> identities = new HashSet<string>(StringComparer.Ordinal);
            int invalid = 0;
            int duplicate = 0;
            for (int index = 1; index < rows.Count; index++)
            {
                IList<string> row = rows[index];
                if (row.All(String.IsNullOrEmpty)) continue;
                if (row.Count != header.Count) { invalid++; continue; }
                try
                {
                    string origin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(row[urlIndex]);
                    BrowserVaultEntry entry = new BrowserVaultEntry
                    {
                        Url = origin,
                        Username = row[usernameIndex] ?? String.Empty,
                        Password = row[passwordIndex] ?? String.Empty,
                        Notes = noteIndex >= 0 ? row[noteIndex] ?? String.Empty : String.Empty
                    };
                    if (BrowserVaultUiPolicy.ValidateEntry(entry) != null) { invalid++; continue; }
                    string identity = origin + "\0" + entry.Username;
                    if (!identities.Add(identity)) { duplicate++; continue; }
                    candidates.Add(entry);
                }
                catch (ArgumentException) { invalid++; }
            }
            return new BrowserCredentialImportPlan
            {
                SourceFormat = format,
                DataRows = rows.Count - 1,
                InvalidRows = invalid,
                DuplicateRows = duplicate,
                Candidates = candidates,
                SourceLength = raw.LongLength,
                SourceSha256 = Sha256(raw)
            };
        }

        internal static bool SourceMatchesPlan(string path, BrowserCredentialImportPlan plan)
        {
            if (plan == null || String.IsNullOrWhiteSpace(plan.SourceSha256)) return false;
            FileInfo file = new FileInfo(Path.GetFullPath(path));
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                file.Length != plan.SourceLength) return false;
            return String.Equals(Sha256(File.ReadAllBytes(file.FullName)), plan.SourceSha256,
                StringComparison.Ordinal);
        }

        private static string Sha256(byte[] value)
        {
            using (SHA256 hash = SHA256.Create())
                return BitConverter.ToString(hash.ComputeHash(value)).Replace("-", String.Empty);
        }

        internal static BrowserCredentialImportResult ImportNoOverwrite(
            IVaultService vault, BrowserCredentialImportPlan plan
        )
        {
            if (vault == null) throw new ArgumentNullException("vault");
            if (plan == null || plan.Candidates == null) throw new ArgumentNullException("plan");
            BrowserVaultStatus status = vault.GetStatus();
            if (status == null || !status.IsAvailable || !status.IsUnlocked)
                throw new InvalidOperationException("Unlock the ZSEC password vault before importing.");
            HashSet<string> existing = new HashSet<string>(
                vault.Search(String.Empty).Select(Identity), StringComparer.Ordinal
            );
            List<string> created = new List<string>();
            int skipped = 0;
            try
            {
                foreach (BrowserVaultEntry candidate in plan.Candidates)
                {
                    string identity = Identity(candidate);
                    if (existing.Contains(identity)) { skipped++; continue; }
                    BrowserVaultEntry saved = vault.Save(candidate.Copy());
                    if (saved == null || String.IsNullOrWhiteSpace(saved.Id))
                        throw new InvalidOperationException("The vault did not confirm an imported credential.");
                    created.Add(saved.Id);
                    existing.Add(identity);
                }
            }
            catch
            {
                foreach (string id in created.AsEnumerable().Reverse())
                {
                    try { vault.Delete(id); } catch (Exception) { }
                }
                throw;
            }
            return new BrowserCredentialImportResult { Imported = created.Count, ExistingSkipped = skipped };
        }

        private static string Identity(BrowserVaultEntry entry)
        {
            return BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(entry.Url) + "\0" +
                (entry.Username ?? String.Empty);
        }

        private static IList<IList<string>> ParseCsv(string text)
        {
            List<IList<string>> rows = new List<IList<string>>();
            List<string> row = new List<string>();
            StringBuilder field = new StringBuilder();
            bool quoted = false;
            for (int index = 0; index < text.Length; index++)
            {
                char value = text[index];
                if (quoted)
                {
                    if (value == '"')
                    {
                        if (index + 1 < text.Length && text[index + 1] == '"')
                        { field.Append('"'); index++; }
                        else quoted = false;
                    }
                    else field.Append(value);
                }
                else if (value == '"')
                {
                    if (field.Length != 0) throw new InvalidDataException("CSV quoting is invalid.");
                    quoted = true;
                }
                else if (value == ',') AddField(row, field);
                else if (value == '\r' || value == '\n')
                {
                    if (value == '\r' && index + 1 < text.Length && text[index + 1] == '\n') index++;
                    AddField(row, field); AddRow(rows, row); row = new List<string>();
                }
                else field.Append(value);
                if (field.Length > BrowserVaultUiPolicy.MaximumPasswordLength * 2)
                    throw new InvalidDataException("A CSV field exceeds its parsing bound.");
            }
            if (quoted) throw new InvalidDataException("CSV quoted field is incomplete.");
            if (field.Length != 0 || row.Count != 0) { AddField(row, field); AddRow(rows, row); }
            return rows;
        }

        private static void AddField(IList<string> row, StringBuilder field)
        {
            if (row.Count >= MaximumColumns) throw new InvalidDataException("CSV column limit exceeded.");
            row.Add(field.ToString()); field.Clear();
        }

        private static void AddRow(IList<IList<string>> rows, IList<string> row)
        {
            if (row.Count == 1 && row[0].Length == 0 && rows.Count > 0) return;
            if (rows.Count >= MaximumRows + 1) throw new InvalidDataException("CSV record limit exceeded.");
            rows.Add(row);
        }
    }
}
