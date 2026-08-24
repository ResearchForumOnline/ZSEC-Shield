using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserSignInCandidate
    {
        public string DisplayName { get; set; }
        public string Origin { get; set; }
        public string Source { get; set; }
    }

    // Produces review-only destinations. This policy never reads cookies, sessions,
    // tokens, browser profiles, or password material.
    internal static class BrowserSignInMigrationPolicy
    {
        internal const int MaximumBatchSize = 20;
        internal const int MaximumCandidateCount = 500;
        internal const int MaximumLocalInputItems = 1000;
        private const int MaximumInputLength = 2048;
        private const int MaximumDisplayLength = 120;

        private static readonly BrowserSignInCandidate[] ReviewedCatalog =
        {
            Catalog("Google", "https://accounts.google.com"),
            Catalog("Gmail", "https://mail.google.com"),
            Catalog("Microsoft", "https://account.microsoft.com"),
            Catalog("Outlook", "https://outlook.live.com"),
            Catalog("Apple", "https://account.apple.com"),
            Catalog("GitHub", "https://github.com"),
            Catalog("Amazon", "https://www.amazon.com"),
            Catalog("X", "https://x.com"),
            Catalog("Facebook", "https://www.facebook.com"),
            Catalog("Instagram", "https://www.instagram.com"),
            Catalog("LinkedIn", "https://www.linkedin.com"),
            Catalog("Dropbox", "https://www.dropbox.com"),
            Catalog("Proton", "https://account.proton.me")
        };

        internal static IList<BrowserSignInCandidate> BuildCandidates(
            IEnumerable<BrowserBookmark> bookmarks,
            IEnumerable<BrowserHistoryEntry> history,
            bool includeReviewedCatalog)
        {
            Dictionary<string, BrowserSignInCandidate> unique =
                new Dictionary<string, BrowserSignInCandidate>(StringComparer.OrdinalIgnoreCase);
            if (includeReviewedCatalog)
                foreach (BrowserSignInCandidate item in ReviewedCatalog)
                    Add(unique, item.DisplayName, item.Origin, item.Source);
            int examined = 0;
            AddBookmarks(unique, bookmarks, ref examined);
            AddHistory(unique, history, ref examined);
            return unique.Values
                .OrderBy(item => item.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.Origin, StringComparer.OrdinalIgnoreCase)
                .Take(MaximumCandidateCount)
                .ToList();
        }

        internal static IList<BrowserSignInCandidate> DiscoverCandidates(
            BrowserProductData data, bool includeReviewedCatalog = true)
        {
            if (data == null) return BuildCandidates(null, null, includeReviewedCatalog);
            return BuildCandidates(data.Bookmarks, data.History, includeReviewedCatalog);
        }

        internal static IList<BrowserSignInCandidate> FilterCandidates(
            IEnumerable<BrowserSignInCandidate> candidates, string query)
        {
            return Search(candidates, query);
        }

        internal static IList<BrowserSignInCandidate> ValidateSelection(
            IEnumerable<BrowserSignInCandidate> selected)
        {
            Dictionary<string, BrowserSignInCandidate> safe =
                new Dictionary<string, BrowserSignInCandidate>(StringComparer.OrdinalIgnoreCase);
            foreach (BrowserSignInCandidate item in selected ?? Enumerable.Empty<BrowserSignInCandidate>())
            {
                if (item == null || !IsKnownSource(item.Source)) continue;
                Add(safe, item.DisplayName, item.Origin, item.Source);
            }
            return safe.Values.Take(MaximumBatchSize).ToList();
        }

        internal static IList<BrowserSignInCandidate> Search(
            IEnumerable<BrowserSignInCandidate> candidates, string query)
        {
            string[] terms = (query ?? String.Empty).Split(
                new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            return (candidates ?? Enumerable.Empty<BrowserSignInCandidate>())
                .Where(item => item != null && terms.All(term =>
                    Contains(item.DisplayName, term) || Contains(item.Origin, term) ||
                    Contains(item.Source, term)))
                .Take(MaximumCandidateCount).ToList();
        }

        internal static bool TryNormalizeHttpsOrigin(string value, out string origin)
        {
            origin = null;
            if (String.IsNullOrWhiteSpace(value) || value.Length > MaximumInputLength ||
                value.Any(Char.IsControl)) return false;
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                !String.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !String.IsNullOrEmpty(uri.UserInfo) || String.IsNullOrWhiteSpace(uri.Host) ||
                uri.IsLoopback || IsObviousLocalHost(uri.Host)) return false;
            origin = uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
            return origin.Length <= MaximumInputLength;
        }

        private static void AddBookmarks(Dictionary<string, BrowserSignInCandidate> unique,
            IEnumerable<BrowserBookmark> items, ref int examined)
        {
            foreach (BrowserBookmark item in items ?? Enumerable.Empty<BrowserBookmark>())
            {
                if (examined >= MaximumLocalInputItems || unique.Count >= MaximumCandidateCount) break;
                examined++;
                if (item != null) Add(unique, item.Title, item.Url, "ZSEC bookmark");
            }
        }

        private static void AddHistory(Dictionary<string, BrowserSignInCandidate> unique,
            IEnumerable<BrowserHistoryEntry> items, ref int examined)
        {
            foreach (BrowserHistoryEntry item in items ?? Enumerable.Empty<BrowserHistoryEntry>())
            {
                if (examined >= MaximumLocalInputItems || unique.Count >= MaximumCandidateCount) break;
                examined++;
                if (item != null) Add(unique, item.Title, item.Url, "ZSEC history");
            }
        }

        private static void Add(Dictionary<string, BrowserSignInCandidate> unique,
            string displayName, string value, string source)
        {
            string origin;
            if (!TryNormalizeHttpsOrigin(value, out origin)) return;
            BrowserSignInCandidate existing;
            string safeName = SafeDisplayName(displayName, origin);
            if (unique.TryGetValue(origin, out existing))
            {
                if (existing.Source.IndexOf(source, StringComparison.OrdinalIgnoreCase) < 0)
                    existing.Source += ", " + source;
                if (existing.DisplayName == existing.Origin && safeName != origin)
                    existing.DisplayName = safeName;
                return;
            }
            unique.Add(origin, new BrowserSignInCandidate
                { DisplayName = safeName, Origin = origin, Source = source });
        }

        private static string SafeDisplayName(string value, string fallback)
        {
            string clean = new string((value ?? String.Empty).Where(character =>
                !Char.IsControl(character) &&
                CharUnicodeInfo.GetUnicodeCategory(character) != UnicodeCategory.Format
            ).ToArray()).Trim();
            if (clean.Length == 0) return fallback;
            return clean.Length <= MaximumDisplayLength ? clean : clean.Substring(0, MaximumDisplayLength);
        }

        private static bool IsObviousLocalHost(string host)
        {
            IPAddress address;
            if (IPAddress.TryParse(host.Trim('[', ']'), out address)) return true;
            string value = host.TrimEnd('.');
            return String.Equals(value, "localhost", StringComparison.OrdinalIgnoreCase) ||
                value.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
                value.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
                value.EndsWith(".internal", StringComparison.OrdinalIgnoreCase) ||
                value.IndexOf('.') < 1;
        }

        private static bool Contains(string value, string term)
        {
            return (value ?? String.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsKnownSource(string source)
        {
            if (String.IsNullOrWhiteSpace(source) || source.Any(Char.IsControl) || source.Length > 64)
                return false;
            return source.Split(',').Select(value => value.Trim()).All(value =>
                value == "ZSEC bookmark" || value == "ZSEC history" ||
                value == "reviewed catalog");
        }

        private static BrowserSignInCandidate Catalog(string name, string origin)
        {
            return new BrowserSignInCandidate
                { DisplayName = name, Origin = origin, Source = "reviewed catalog" };
        }
    }
}
