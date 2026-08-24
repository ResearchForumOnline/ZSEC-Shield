using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserVaultEntry
    {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public string Url { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Notes { get; set; }
        public string UpdatedAtUtc { get; set; }

        internal BrowserVaultEntry Copy()
        {
            return new BrowserVaultEntry
            {
                Id = Id,
                DisplayName = DisplayName,
                Url = Url,
                Username = Username,
                Password = Password,
                Notes = Notes,
                UpdatedAtUtc = UpdatedAtUtc
            };
        }
    }

    internal sealed class BrowserVaultStatus
    {
        public bool IsAvailable { get; set; }
        public bool IsUnlocked { get; set; }
        public int EntryCount { get; set; }
        public string Message { get; set; }
    }

    internal sealed class BrowserPasswordGenerationOptions
    {
        public int Length { get; set; }
        public bool IncludeUppercase { get; set; }
        public bool IncludeLowercase { get; set; }
        public bool IncludeDigits { get; set; }
        public bool IncludeSymbols { get; set; }

        internal static BrowserPasswordGenerationOptions CreateDefault()
        {
            return new BrowserPasswordGenerationOptions
            {
                Length = 24,
                IncludeUppercase = true,
                IncludeLowercase = true,
                IncludeDigits = true,
                IncludeSymbols = true
            };
        }
    }

    internal interface IVaultService
    {
        BrowserVaultStatus GetStatus();
        IList<BrowserVaultEntry> Search(string query);
        BrowserVaultEntry Get(string id);
        BrowserVaultEntry Save(BrowserVaultEntry entry);
        void Delete(string id);
        void Unlock();
        void Lock();
        string GeneratePassword(BrowserPasswordGenerationOptions options);
    }

    internal interface IBrowserClipboard
    {
        void SetSensitiveText(string value);
        bool ClearIfUnchanged(string expectedValue);
    }

    internal static class BrowserVaultUiPolicy
    {
        internal const int MaximumUrlLength = 2048;
        internal const int MaximumDisplayNameLength = 256;
        internal const int MaximumUsernameLength = 320;
        internal const int MaximumPasswordLength = 4096;
        internal const int MaximumNotesLength = 4096;
        internal const int MaximumSearchLength = 256;
        internal const int MinimumGeneratedPasswordLength = 12;
        internal const int MaximumGeneratedPasswordLength = 128;
        internal const int ClipboardSeconds = 30;
        internal const int RevealSeconds = 15;
        internal const int DefaultAutoLockMinutes = 5;

        internal static string NormalizeSearch(string query)
        {
            string normalized = (query ?? String.Empty).Trim();
            if (normalized.Length > MaximumSearchLength)
            {
                normalized = normalized.Substring(0, MaximumSearchLength);
            }
            return normalized;
        }

        internal static bool Matches(BrowserVaultEntry entry, string query)
        {
            if (entry == null) return false;
            string normalized = NormalizeSearch(query);
            if (normalized.Length == 0) return true;
            string[] terms = normalized.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            return terms.All(term =>
                Contains(entry.DisplayName, term) || Contains(entry.Url, term) ||
                Contains(DisplaySite(entry.Url), term) || Contains(entry.Username, term) ||
                Contains(entry.Notes, term)
            );
        }

        internal static string ValidateEntry(BrowserVaultEntry entry)
        {
            if (entry == null) return "A password entry is required.";
            string url = (entry.Url ?? String.Empty).Trim();
            if (url.Length == 0) return "Enter the website address.";
            if (url.Length > MaximumUrlLength) return "The website address is too long.";
            if ((entry.DisplayName ?? String.Empty).Length > MaximumDisplayNameLength)
                return "The display name is too long.";
            Uri parsed;
            if (!Uri.TryCreate(url, UriKind.Absolute, out parsed) ||
                (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
            {
                return "The website address must begin with https:// or http://.";
            }
            if ((entry.Username ?? String.Empty).Length > MaximumUsernameLength)
            {
                return "The username is too long.";
            }
            int passwordLength = (entry.Password ?? String.Empty).Length;
            if (passwordLength == 0) return "Enter or generate a password.";
            if (passwordLength > MaximumPasswordLength) return "The password is too long.";
            if ((entry.Notes ?? String.Empty).Length > MaximumNotesLength)
            {
                return "The notes are too long.";
            }
            return null;
        }

        internal static string ValidateGenerationOptions(BrowserPasswordGenerationOptions options)
        {
            if (options == null) return "Password generation options are required.";
            if (options.Length < MinimumGeneratedPasswordLength ||
                options.Length > MaximumGeneratedPasswordLength)
            {
                return String.Format(
                    CultureInfo.InvariantCulture,
                    "Password length must be between {0} and {1} characters.",
                    MinimumGeneratedPasswordLength,
                    MaximumGeneratedPasswordLength
                );
            }
            if (!options.IncludeUppercase && !options.IncludeLowercase &&
                !options.IncludeDigits && !options.IncludeSymbols)
            {
                return "Select at least one character group.";
            }
            return null;
        }

        internal static string DisplaySite(string url)
        {
            Uri parsed;
            if (Uri.TryCreate(url, UriKind.Absolute, out parsed) &&
                !String.IsNullOrWhiteSpace(parsed.Host))
            {
                return parsed.Host;
            }
            return url ?? String.Empty;
        }

        private static bool Contains(string value, string query)
        {
            return (value ?? String.Empty).IndexOf(
                query,
                StringComparison.OrdinalIgnoreCase
            ) >= 0;
        }
    }

    internal sealed class BrowserVaultAutoLockController
    {
        private readonly TimeSpan idleTimeout;
        private DateTime lastActivityUtc;

        internal BrowserVaultAutoLockController(int minutes, DateTime nowUtc)
        {
            if (minutes < 1 || minutes > 120)
            {
                throw new ArgumentOutOfRangeException("minutes");
            }
            idleTimeout = TimeSpan.FromMinutes(minutes);
            Touch(nowUtc);
        }

        internal void Touch(DateTime nowUtc)
        {
            if (nowUtc.Kind != DateTimeKind.Utc)
            {
                throw new ArgumentException("Activity time must use UTC.", "nowUtc");
            }
            if (nowUtc > lastActivityUtc) lastActivityUtc = nowUtc;
        }

        internal bool ShouldLock(DateTime nowUtc)
        {
            if (nowUtc.Kind != DateTimeKind.Utc)
            {
                throw new ArgumentException("Lock-check time must use UTC.", "nowUtc");
            }
            return nowUtc - lastActivityUtc >= idleTimeout;
        }
    }

    internal sealed class BrowserSensitiveClipboardController
    {
        private readonly IBrowserClipboard clipboard;
        private string pendingValue;

        internal BrowserSensitiveClipboardController(IBrowserClipboard clipboardService)
        {
            if (clipboardService == null) throw new ArgumentNullException("clipboardService");
            clipboard = clipboardService;
        }

        internal bool HasPendingValue { get { return pendingValue != null; } }

        internal void Copy(string value)
        {
            if (String.IsNullOrEmpty(value)) throw new ArgumentException("Clipboard text is empty.");
            ClearPending();
            clipboard.SetSensitiveText(value);
            pendingValue = value;
        }

        internal bool ClearPending()
        {
            string value = pendingValue;
            pendingValue = null;
            return value != null && clipboard.ClearIfUnchanged(value);
        }
    }

    internal sealed class BrowserSecretRevealController
    {
        private readonly TimeSpan revealTimeout;
        private DateTime? revealedAtUtc;

        internal BrowserSecretRevealController(int seconds)
        {
            if (seconds < 1 || seconds > 60) throw new ArgumentOutOfRangeException("seconds");
            revealTimeout = TimeSpan.FromSeconds(seconds);
        }

        internal bool IsRevealed { get { return revealedAtUtc.HasValue; } }

        internal void Reveal(DateTime nowUtc)
        {
            RequireUtc(nowUtc);
            revealedAtUtc = nowUtc;
        }

        internal void Conceal()
        {
            revealedAtUtc = null;
        }

        internal bool ShouldConceal(DateTime nowUtc)
        {
            RequireUtc(nowUtc);
            return revealedAtUtc.HasValue && nowUtc - revealedAtUtc.Value >= revealTimeout;
        }

        private static void RequireUtc(DateTime value)
        {
            if (value.Kind != DateTimeKind.Utc)
                throw new ArgumentException("Reveal time must use UTC.", "value");
        }
    }
}
