using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace TalkToAI.ZsecBrowserPreview
{
    internal enum BrowserCredentialMessageKind
    {
        SaveCandidate,
        FillRequest
    }

    internal enum BrowserCredentialPromptKind
    {
        None,
        Save,
        Update
    }

    internal enum BrowserCredentialPromptDecision
    {
        Save,
        Update,
        NotNow,
        NeverForSite
    }

    internal sealed class BrowserCredentialMessage
    {
        public BrowserCredentialMessageKind Kind { get; private set; }
        public string RequestId { get; private set; }
        public string Origin { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }

        internal static BrowserCredentialMessage Parse(string json, Uri sourceUri)
        {
            if (String.IsNullOrWhiteSpace(json))
                throw new InvalidDataException("Credential message is empty.");
            if (Encoding.UTF8.GetByteCount(json) > BrowserCredentialWorkflowPolicy.MaximumMessageBytes)
                throw new InvalidDataException("Credential message exceeds its size limit.");
            string sourceOrigin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(sourceUri);
            JavaScriptSerializer serializer = new JavaScriptSerializer
            {
                MaxJsonLength = BrowserCredentialWorkflowPolicy.MaximumMessageBytes,
                RecursionLimit = 8
            };
            object decoded;
            try { decoded = serializer.DeserializeObject(json); }
            catch (Exception exception)
            {
                if (exception is ArgumentException || exception is InvalidOperationException)
                    throw new InvalidDataException("Credential message is invalid JSON.", exception);
                throw;
            }
            Dictionary<string, object> root = decoded as Dictionary<string, object>;
            if (root == null) throw new InvalidDataException("Credential message must be an object.");
            string schema = Text(root, "schema", 80, false);
            BrowserCredentialMessage result = new BrowserCredentialMessage();
            if (schema == "zsec.browser.credential-save-candidate.v1")
            {
                Exact(root, "schema", "request_id", "origin", "username", "password");
                result.Kind = BrowserCredentialMessageKind.SaveCandidate;
                result.Username = Text(root, "username", BrowserVaultUiPolicy.MaximumUsernameLength, true);
                result.Password = Text(root, "password", BrowserVaultUiPolicy.MaximumPasswordLength, false);
            }
            else if (schema == "zsec.browser.credential-fill-request.v1")
            {
                Exact(root, "schema", "request_id", "origin");
                result.Kind = BrowserCredentialMessageKind.FillRequest;
            }
            else
            {
                throw new InvalidDataException("Credential message schema is unsupported.");
            }
            result.RequestId = Text(root, "request_id", 32, false);
            Guid request;
            if (!Guid.TryParseExact(result.RequestId, "N", out request))
                throw new InvalidDataException("Credential request ID is invalid.");
            result.RequestId = request.ToString("N");
            Uri declaredUri;
            if (!Uri.TryCreate(Text(root, "origin", 2048, false), UriKind.Absolute, out declaredUri))
                throw new InvalidDataException("Credential message origin is invalid.");
            string declaredOrigin;
            try { declaredOrigin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(declaredUri); }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Credential message origin is invalid.", exception);
            }
            if (!String.Equals(declaredOrigin, sourceOrigin, StringComparison.Ordinal))
                throw new InvalidDataException("Credential message origin does not match its source.");
            result.Origin = sourceOrigin;
            return result;
        }

        private static void Exact(Dictionary<string, object> value, params string[] keys)
        {
            if (value.Count != keys.Length || keys.Any(key => !value.ContainsKey(key)))
                throw new InvalidDataException("Credential message fields are invalid.");
        }

        private static string Text(
            Dictionary<string, object> value, string key, int maximum, bool allowEmpty
        )
        {
            object raw;
            string text;
            if (!value.TryGetValue(key, out raw) || (text = raw as string) == null ||
                text.Length > maximum || (!allowEmpty && text.Length == 0) || text.IndexOf('\0') >= 0)
                throw new InvalidDataException("Credential message field is invalid: " + key + ".");
            return text;
        }
    }

    internal sealed class BrowserCredentialPromptPlan
    {
        public BrowserCredentialPromptKind Kind { get; internal set; }
        public string Origin { get; internal set; }
        public string ExistingEntryId { get; internal set; }
        public string Reason { get; internal set; }
    }

    internal sealed class BrowserCredentialRequestTracker
    {
        private const int MaximumPending = 128;
        private readonly HashSet<string> pending = new HashSet<string>(StringComparer.Ordinal);
        private readonly object gate = new object();

        internal string Issue()
        {
            lock (gate)
            {
                if (pending.Count >= MaximumPending)
                    throw new InvalidOperationException("Credential request limit reached.");
                string requestId;
                do { requestId = Guid.NewGuid().ToString("N"); }
                while (!pending.Add(requestId));
                return requestId;
            }
        }

        internal bool Consume(string requestId)
        {
            Guid parsed;
            if (!Guid.TryParseExact(requestId, "N", out parsed)) return false;
            lock (gate) { return pending.Remove(parsed.ToString("N")); }
        }

        internal void Clear()
        {
            lock (gate) { pending.Clear(); }
        }
    }

    internal static class BrowserCredentialWorkflowPolicy
    {
        internal const int MaximumMessageBytes = 24 * 1024;
        internal const int MaximumNeverSaveOrigins = 500;

        internal static string NormalizeSecureOrigin(Uri uri)
        {
            if (uri == null || !uri.IsAbsoluteUri ||
                !String.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                String.IsNullOrWhiteSpace(uri.Host) || !String.IsNullOrEmpty(uri.UserInfo))
                throw new ArgumentException("Credential workflows require an absolute HTTPS origin.", "uri");
            string host = new UriBuilder(Uri.UriSchemeHttps, uri.IdnHost).Host.ToLowerInvariant();
            int port = uri.IsDefaultPort ? -1 : uri.Port;
            UriBuilder normalized = new UriBuilder(Uri.UriSchemeHttps, host, port)
            {
                Path = String.Empty,
                Query = String.Empty,
                Fragment = String.Empty,
                UserName = String.Empty,
                Password = String.Empty
            };
            return normalized.Uri.GetLeftPart(UriPartial.Authority).TrimEnd('/').ToLowerInvariant();
        }

        internal static string NormalizeSecureOrigin(string value)
        {
            Uri uri;
            if (String.IsNullOrWhiteSpace(value) || value.Length > 2048 ||
                !Uri.TryCreate(value, UriKind.Absolute, out uri))
                throw new ArgumentException("Credential origin is invalid.", "value");
            return NormalizeSecureOrigin(uri);
        }

        internal static bool IsNeverSaveOrigin(BrowserSettings settings, string origin)
        {
            if (settings == null) throw new ArgumentNullException("settings");
            string normalized = NormalizeSecureOrigin(origin);
            return (settings.PasswordNeverSaveOrigins ?? new List<string>()).Contains(
                normalized, StringComparer.Ordinal
            );
        }

        internal static bool SetNeverSaveOrigin(BrowserSettings settings, string origin, bool excluded)
        {
            if (settings == null) throw new ArgumentNullException("settings");
            string normalized = NormalizeSecureOrigin(origin);
            List<string> values = NormalizeNeverSaveOrigins(settings.PasswordNeverSaveOrigins);
            bool changed;
            if (excluded)
            {
                if (values.Contains(normalized, StringComparer.Ordinal)) changed = false;
                else
                {
                    if (values.Count >= MaximumNeverSaveOrigins)
                        throw new InvalidOperationException("Never-save site limit reached.");
                    values.Add(normalized);
                    changed = true;
                }
            }
            else changed = values.RemoveAll(item => item == normalized) > 0;
            settings.PasswordNeverSaveOrigins = values.OrderBy(
                item => item, StringComparer.Ordinal
            ).ToList();
            return changed;
        }

        internal static List<string> NormalizeNeverSaveOrigins(IEnumerable<string> values)
        {
            List<string> normalized = new List<string>();
            if (values == null) return normalized;
            foreach (string value in values.Take(MaximumNeverSaveOrigins + 1))
            {
                if (normalized.Count >= MaximumNeverSaveOrigins) break;
                try
                {
                    string origin = NormalizeSecureOrigin(value);
                    if (!normalized.Contains(origin, StringComparer.Ordinal)) normalized.Add(origin);
                }
                catch (ArgumentException) { }
            }
            return normalized.OrderBy(item => item, StringComparer.Ordinal).ToList();
        }

        internal static BrowserCredentialPromptPlan EvaluateSavePrompt(
            BrowserSettings settings,
            BrowserCredentialMessage message,
            IEnumerable<BrowserVaultEntry> existingEntries
        )
        {
            if (settings == null) throw new ArgumentNullException("settings");
            if (message == null || message.Kind != BrowserCredentialMessageKind.SaveCandidate)
                throw new ArgumentException("A validated save-candidate message is required.", "message");
            if (!settings.PasswordSaveEnabled)
                return None(message.Origin, "password saving is disabled");
            if (IsNeverSaveOrigin(settings, message.Origin))
                return None(message.Origin, "site is on the never-save list");
            BrowserVaultEntry existing = (existingEntries ?? Enumerable.Empty<BrowserVaultEntry>())
                .FirstOrDefault(entry => EntryMatchesExactOrigin(entry, message.Origin) &&
                    String.Equals(entry.Username ?? String.Empty, message.Username, StringComparison.Ordinal));
            if (existing != null && String.Equals(existing.Password, message.Password, StringComparison.Ordinal))
                return None(message.Origin, "stored credential is unchanged");
            return new BrowserCredentialPromptPlan
            {
                Kind = existing == null ? BrowserCredentialPromptKind.Save : BrowserCredentialPromptKind.Update,
                Origin = message.Origin,
                ExistingEntryId = existing == null ? null : existing.Id,
                Reason = existing == null ? "new exact-origin credential" : "password changed"
            };
        }

        internal static void ApplyPromptDecision(
            BrowserSettings settings, string origin, BrowserCredentialPromptDecision decision
        )
        {
            if (settings == null) throw new ArgumentNullException("settings");
            if (decision == BrowserCredentialPromptDecision.NeverForSite)
                SetNeverSaveOrigin(settings, origin, true);
        }

        internal static BrowserVaultEntry BuildAcceptedSave(
            BrowserCredentialMessage message,
            BrowserCredentialPromptPlan plan,
            BrowserCredentialPromptDecision decision,
            BrowserVaultEntry existingEntry
        )
        {
            if (message == null || message.Kind != BrowserCredentialMessageKind.SaveCandidate)
                throw new ArgumentException("A validated save candidate is required.", "message");
            if (plan == null || !String.Equals(plan.Origin, message.Origin, StringComparison.Ordinal))
                throw new InvalidOperationException("Save prompt plan does not match the candidate.");
            if (decision == BrowserCredentialPromptDecision.NotNow ||
                decision == BrowserCredentialPromptDecision.NeverForSite)
                return null;
            if (plan.Kind == BrowserCredentialPromptKind.Save &&
                decision == BrowserCredentialPromptDecision.Save)
            {
                if (existingEntry != null)
                    throw new InvalidOperationException("New-save decision received an existing entry.");
                return new BrowserVaultEntry
                {
                    Url = message.Origin,
                    Username = message.Username,
                    Password = message.Password,
                    Notes = String.Empty
                };
            }
            if (plan.Kind == BrowserCredentialPromptKind.Update &&
                decision == BrowserCredentialPromptDecision.Update)
            {
                if (existingEntry == null ||
                    !String.Equals(existingEntry.Id, plan.ExistingEntryId, StringComparison.Ordinal) ||
                    !EntryMatchesExactOrigin(existingEntry, message.Origin) ||
                    !String.Equals(
                        existingEntry.Username ?? String.Empty,
                        message.Username,
                        StringComparison.Ordinal
                    ))
                    throw new InvalidOperationException("Update decision does not match the stored entry.");
                BrowserVaultEntry update = existingEntry.Copy();
                update.Password = message.Password;
                return update;
            }
            throw new InvalidOperationException("Prompt decision is inconsistent with its plan.");
        }

        internal static IList<BrowserVaultEntry> SelectAutofillEntries(
            BrowserSettings settings,
            Uri sourceUri,
            bool isTopLevelDocument,
            IEnumerable<BrowserVaultEntry> entries
        )
        {
            if (settings == null) throw new ArgumentNullException("settings");
            if (!settings.PasswordAutofillEnabled || !isTopLevelDocument)
                return new List<BrowserVaultEntry>();
            string origin = NormalizeSecureOrigin(sourceUri);
            return (entries ?? Enumerable.Empty<BrowserVaultEntry>())
                .Where(entry => EntryMatchesExactOrigin(entry, origin))
                .Select(entry => entry.Copy())
                .Take(20)
                .ToList();
        }

        internal static bool EntryMatchesExactOrigin(BrowserVaultEntry entry, string origin)
        {
            if (entry == null) return false;
            try
            {
                return String.Equals(
                    NormalizeSecureOrigin(entry.Url),
                    NormalizeSecureOrigin(origin),
                    StringComparison.Ordinal
                );
            }
            catch (ArgumentException) { return false; }
        }

        private static BrowserCredentialPromptPlan None(string origin, string reason)
        {
            return new BrowserCredentialPromptPlan
            {
                Kind = BrowserCredentialPromptKind.None,
                Origin = origin,
                ExistingEntryId = null,
                Reason = reason
            };
        }
    }
}
