using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Script.Serialization;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserBookmark
    {
        public string Title { get; set; }
        public string Url { get; set; }
        public string CreatedAtUtc { get; set; }
    }

    internal sealed class BrowserHistoryEntry
    {
        public string Title { get; set; }
        public string Url { get; set; }
        public string VisitedAtUtc { get; set; }
        public int TypedCount { get; set; }
    }

    internal sealed class BrowserSettings
    {
        public string StartupMode { get; set; }
        public string CustomStartupUrl { get; set; }
        public bool RecordHistory { get; set; }
        public bool ClearHistoryOnExit { get; set; }
        public bool ShowBookmarksBar { get; set; }
        public bool MinimizeToTray { get; set; }
        public bool CloseToTray { get; set; }
        public bool AskDownloadLocation { get; set; }
        public string DownloadDirectory { get; set; }
        public bool NativeStrictMode { get; set; }
        public bool BlockYoutubeAds { get; set; }
        public string SearchEngine { get; set; }
        public bool PasswordSaveEnabled { get; set; }
        public bool PasswordAutofillEnabled { get; set; }
        public List<string> PasswordNeverSaveOrigins { get; set; }
        public string Theme { get; set; }
        public string AccentColor { get; set; }

        internal static BrowserSettings CreateDefault()
        {
            return new BrowserSettings
            {
                StartupMode = "home",
                CustomStartupUrl = "https://talktoai.org/zero-browser/",
                RecordHistory = true,
                ClearHistoryOnExit = false,
                ShowBookmarksBar = true,
                MinimizeToTray = true,
                CloseToTray = false,
                AskDownloadLocation = true,
                DownloadDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Downloads"
                ),
                NativeStrictMode = false,
                BlockYoutubeAds = true,
                SearchEngine = "brave",
                PasswordSaveEnabled = false,
                PasswordAutofillEnabled = false,
                PasswordNeverSaveOrigins = new List<string>(),
                Theme = "soft_dark",
                AccentColor = "teal"
            };
        }

        internal BrowserSettings Copy()
        {
            return new BrowserSettings
            {
                StartupMode = StartupMode,
                CustomStartupUrl = CustomStartupUrl,
                RecordHistory = RecordHistory,
                ClearHistoryOnExit = ClearHistoryOnExit,
                ShowBookmarksBar = ShowBookmarksBar,
                MinimizeToTray = MinimizeToTray,
                CloseToTray = CloseToTray,
                AskDownloadLocation = AskDownloadLocation,
                DownloadDirectory = DownloadDirectory,
                NativeStrictMode = NativeStrictMode,
                BlockYoutubeAds = BlockYoutubeAds,
                SearchEngine = SearchEngine,
                PasswordSaveEnabled = PasswordSaveEnabled,
                PasswordAutofillEnabled = PasswordAutofillEnabled,
                PasswordNeverSaveOrigins = new List<string>(
                    PasswordNeverSaveOrigins ?? new List<string>()
                ),
                Theme = Theme,
                AccentColor = AccentColor
            };
        }
    }

    internal sealed class BrowserProductData
    {
        public int SchemaVersion { get; set; }
        public List<BrowserBookmark> Bookmarks { get; set; }
        public List<BrowserHistoryEntry> History { get; set; }
        public BrowserSettings Settings { get; set; }

        internal static BrowserProductData CreateDefault()
        {
            return new BrowserProductData
            {
                SchemaVersion = 3,
                Bookmarks = new List<BrowserBookmark>(),
                History = new List<BrowserHistoryEntry>(),
                Settings = BrowserSettings.CreateDefault()
            };
        }
    }

    internal sealed class BrowserDataStore
    {
        internal const int MaximumBookmarks = 1000;
        internal const int MaximumHistoryEntries = 5000;
        internal const int MaximumStateBytes = 4 * 1024 * 1024;
        internal const int MaximumImportBytes = 8 * 1024 * 1024;

        private static readonly Regex BookmarkAnchor = new Regex(
            "<a\\b[^>]*\\bhref\\s*=\\s*(?:\\\"(?<double>[^\\\"]*)\\\"|'(?<single>[^']*)')[^>]*>(?<title>.*?)</a>",
            RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant
        );
        private static readonly Regex HtmlTag = new Regex(
            @"<[^>]+>",
            RegexOptions.Singleline | RegexOptions.CultureInvariant
        );

        private readonly string root;
        private readonly string statePath;
        private readonly JavaScriptSerializer serializer;

        internal BrowserDataStore(string productRoot)
        {
            if (String.IsNullOrWhiteSpace(productRoot))
            {
                throw new ArgumentException("A product data root is required.", "productRoot");
            }
            root = Path.GetFullPath(productRoot);
            statePath = Path.Combine(root, "browser-data.json");
            serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = MaximumStateBytes;
        }

        internal string StatePath
        {
            get { return statePath; }
        }

        internal BrowserProductData Load()
        {
            if (!Directory.Exists(root)) return BrowserProductData.CreateDefault();
            RejectReparseDirectory(root);
            if (!File.Exists(statePath)) return BrowserProductData.CreateDefault();
            FileInfo file = new FileInfo(statePath);
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("ZSEC refused a reparse-point browser data file.");
            }
            if (file.Length <= 0 || file.Length > MaximumStateBytes)
            {
                throw new InvalidDataException("The ZSEC browser data file has an invalid size.");
            }
            BrowserProductData data = serializer.Deserialize<BrowserProductData>(
                File.ReadAllText(statePath, Encoding.UTF8)
            );
            return Normalize(data);
        }

        internal void Save(BrowserProductData data)
        {
            BrowserProductData normalized = Normalize(data);
            EnsureRoot();
            string json = serializer.Serialize(normalized);
            byte[] bytes = new UTF8Encoding(false).GetBytes(json + Environment.NewLine);
            if (bytes.Length > MaximumStateBytes)
            {
                throw new InvalidOperationException("The ZSEC browser data file exceeds its safety bound.");
            }
            string temporary = statePath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllBytes(temporary, bytes);
                if (File.Exists(statePath)) File.Replace(temporary, statePath, null);
                else File.Move(temporary, statePath);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        internal bool AddBookmark(BrowserProductData data, string title, string url)
        {
            Uri parsed;
            if (!TryNormalizeWebUrl(url, out parsed)) return false;
            string normalizedUrl = parsed.AbsoluteUri;
            BrowserBookmark existing = data.Bookmarks.FirstOrDefault(item =>
                String.Equals(item.Url, normalizedUrl, StringComparison.OrdinalIgnoreCase)
            );
            string safeTitle = NormalizeTitle(title, parsed.Host);
            if (existing != null)
            {
                existing.Title = safeTitle;
                Save(data);
                return false;
            }
            data.Bookmarks.Insert(0, new BrowserBookmark
            {
                Title = safeTitle,
                Url = normalizedUrl,
                CreatedAtUtc = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            });
            if (data.Bookmarks.Count > MaximumBookmarks)
            {
                data.Bookmarks.RemoveRange(MaximumBookmarks, data.Bookmarks.Count - MaximumBookmarks);
            }
            Save(data);
            return true;
        }

        internal bool RemoveBookmark(BrowserProductData data, string url)
        {
            int removed = data.Bookmarks.RemoveAll(item =>
                String.Equals(item.Url, url, StringComparison.OrdinalIgnoreCase)
            );
            if (removed > 0) Save(data);
            return removed > 0;
        }

        internal static IReadOnlyList<BrowserBookmark> SearchBookmarks(
            IEnumerable<BrowserBookmark> bookmarks,
            string query
        )
        {
            List<BrowserBookmark> source = (bookmarks ?? Enumerable.Empty<BrowserBookmark>())
                .Where(item => item != null)
                .ToList();
            string normalized = (query ?? String.Empty).Trim();
            if (normalized.Length == 0) return source;
            if (normalized.Length > 256) normalized = normalized.Substring(0, 256);
            string[] terms = normalized.Split(
                new[] { ' ', '\t', '\r', '\n' },
                StringSplitOptions.RemoveEmptyEntries
            );
            return source.Where(bookmark =>
            {
                string host = String.Empty;
                Uri parsed;
                if (TryNormalizeWebUrl(bookmark.Url, out parsed)) host = parsed.Host;
                string searchable = String.Join("\n", new[]
                {
                    bookmark.Title ?? String.Empty,
                    bookmark.Url ?? String.Empty,
                    host
                });
                return terms.All(term => searchable.IndexOf(
                    term,
                    StringComparison.OrdinalIgnoreCase
                ) >= 0);
            }).ToList();
        }

        internal void AddHistory(BrowserProductData data, string title, string url)
        {
            AddHistory(data, title, url, false);
        }

        internal void AddHistory(BrowserProductData data, string title, string url, bool typed)
        {
            if (!data.Settings.RecordHistory) return;
            Uri parsed;
            if (!TryNormalizeWebUrl(url, out parsed)) return;
            string normalizedUrl = parsed.AbsoluteUri;
            BrowserHistoryEntry existing = data.History.FirstOrDefault(item =>
                item != null && String.Equals(item.Url, normalizedUrl, StringComparison.OrdinalIgnoreCase)
            );
            int typedCount = typed ? 1 : 0;
            if (existing != null)
            {
                typedCount += Math.Max(0, existing.TypedCount);
                data.History.Remove(existing);
            }
            data.History.Insert(0, new BrowserHistoryEntry
            {
                Title = NormalizeTitle(title, parsed.Host),
                Url = normalizedUrl,
                VisitedAtUtc = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                TypedCount = typedCount
            });
            if (data.History.Count > MaximumHistoryEntries)
            {
                data.History.RemoveRange(
                    MaximumHistoryEntries,
                    data.History.Count - MaximumHistoryEntries
                );
            }
            Save(data);
        }

        internal void ClearHistory(BrowserProductData data)
        {
            data.History.Clear();
            Save(data);
        }

        internal IReadOnlyList<string> GetAddressSuggestions(
            BrowserProductData data,
            string input,
            int maximum
        )
        {
            if (data == null || maximum <= 0) return new List<string>();
            string term = (input ?? String.Empty).Trim();
            IEnumerable<Tuple<string, int, int>> history = data.History
                .Where(item => item != null)
                .Select((item, index) => Tuple.Create(
                    item.Url,
                    Math.Max(0, item.TypedCount),
                    index
                ));
            IEnumerable<Tuple<string, int, int>> bookmarks = data.Bookmarks
                .Where(item => item != null)
                .Select((item, index) => Tuple.Create(item.Url, 0, index + 100000));
            return history.Concat(bookmarks)
                .Where(item => !String.IsNullOrWhiteSpace(item.Item1))
                .GroupBy(item => item.Item1, StringComparer.OrdinalIgnoreCase)
                .Select(group => group
                    .OrderByDescending(item => item.Item2)
                    .ThenBy(item => item.Item3)
                    .First())
                .Where(item => AddressSuggestionMatches(item.Item1, term))
                .OrderByDescending(item => item.Item2)
                .ThenBy(item => item.Item3)
                .SelectMany(item => AddressSuggestionForms(item.Item1))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(Math.Min(maximum, 2000))
                .ToList();
        }

        internal int ImportBookmarksHtml(BrowserProductData data, string path)
        {
            FileInfo file = GetRegularBoundedFile(path, MaximumImportBytes);
            string html = File.ReadAllText(file.FullName, Encoding.UTF8);
            int added = 0;
            foreach (Match match in BookmarkAnchor.Matches(html))
            {
                if (data.Bookmarks.Count >= MaximumBookmarks) break;
                string candidate = match.Groups["double"].Success
                    ? match.Groups["double"].Value
                    : match.Groups["single"].Value;
                candidate = HttpUtility.HtmlDecode(candidate);
                Uri parsed;
                if (!TryNormalizeWebUrl(candidate, out parsed)) continue;
                if (data.Bookmarks.Any(item =>
                    String.Equals(item.Url, parsed.AbsoluteUri, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }
                string title = HttpUtility.HtmlDecode(
                    HtmlTag.Replace(match.Groups["title"].Value, String.Empty)
                );
                data.Bookmarks.Add(new BrowserBookmark
                {
                    Title = NormalizeTitle(title, parsed.Host),
                    Url = parsed.AbsoluteUri,
                    CreatedAtUtc = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                });
                added++;
            }
            if (added > 0) Save(data);
            return added;
        }

        internal void ExportBookmarksHtml(BrowserProductData data, string path)
        {
            string fullPath = Path.GetFullPath(path);
            string parent = Path.GetDirectoryName(fullPath);
            if (String.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
            {
                throw new DirectoryNotFoundException("The bookmark export directory does not exist.");
            }
            StringBuilder output = new StringBuilder();
            output.AppendLine("<!DOCTYPE NETSCAPE-Bookmark-file-1>");
            output.AppendLine("<meta charset=\"UTF-8\">");
            output.AppendLine("<title>ZSEC Browser Bookmarks</title>");
            output.AppendLine("<h1>ZSEC Browser Bookmarks</h1>");
            output.AppendLine("<dl><p>");
            foreach (BrowserBookmark bookmark in data.Bookmarks)
            {
                Uri parsed;
                if (!TryNormalizeWebUrl(bookmark.Url, out parsed)) continue;
                output.Append("  <dt><a href=\"");
                output.Append(HttpUtility.HtmlAttributeEncode(parsed.AbsoluteUri));
                output.Append("\">");
                output.Append(HttpUtility.HtmlEncode(NormalizeTitle(bookmark.Title, parsed.Host)));
                output.AppendLine("</a>");
            }
            output.AppendLine("</dl><p>");
            string temporary = fullPath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllText(temporary, output.ToString(), new UTF8Encoding(false));
                if (File.Exists(fullPath)) File.Replace(temporary, fullPath, null);
                else File.Move(temporary, fullPath);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        internal static bool TryNormalizeWebUrl(string candidate, out Uri parsed)
        {
            parsed = null;
            if (String.IsNullOrWhiteSpace(candidate) || candidate.Length > 4096) return false;
            Uri value;
            if (!Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out value)) return false;
            if (value.Scheme != Uri.UriSchemeHttps && value.Scheme != Uri.UriSchemeHttp) return false;
            if (String.IsNullOrWhiteSpace(value.Host)) return false;
            parsed = value;
            return true;
        }

        private BrowserProductData Normalize(BrowserProductData data)
        {
            if (data == null) data = BrowserProductData.CreateDefault();
            bool legacySchema = data.SchemaVersion < 2;
            data.SchemaVersion = 3;
            if (data.Settings == null) data.Settings = BrowserSettings.CreateDefault();
            else if (legacySchema) data.Settings.BlockYoutubeAds = true;
            NormalizeSettings(data.Settings);
            if (data.Bookmarks == null) data.Bookmarks = new List<BrowserBookmark>();
            if (data.History == null) data.History = new List<BrowserHistoryEntry>();

            data.Bookmarks = data.Bookmarks
                .Where(item => item != null)
                .Select(NormalizeBookmark)
                .Where(item => item != null)
                .GroupBy(item => item.Url, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Take(MaximumBookmarks)
                .ToList();
            data.History = data.History
                .Where(item => item != null)
                .Select(NormalizeHistory)
                .Where(item => item != null)
                .Take(MaximumHistoryEntries)
                .ToList();
            return data;
        }

        private static BrowserBookmark NormalizeBookmark(BrowserBookmark item)
        {
            Uri parsed;
            if (!TryNormalizeWebUrl(item.Url, out parsed)) return null;
            return new BrowserBookmark
            {
                Title = NormalizeTitle(item.Title, parsed.Host),
                Url = parsed.AbsoluteUri,
                CreatedAtUtc = NormalizeTimestamp(item.CreatedAtUtc)
            };
        }

        private static BrowserHistoryEntry NormalizeHistory(BrowserHistoryEntry item)
        {
            Uri parsed;
            if (!TryNormalizeWebUrl(item.Url, out parsed)) return null;
            return new BrowserHistoryEntry
            {
                Title = NormalizeTitle(item.Title, parsed.Host),
                Url = parsed.AbsoluteUri,
                VisitedAtUtc = NormalizeTimestamp(item.VisitedAtUtc),
                TypedCount = Math.Max(0, item.TypedCount)
            };
        }

        private static void NormalizeSettings(BrowserSettings settings)
        {
            string mode = (settings.StartupMode ?? String.Empty).Trim().ToLowerInvariant();
            if (mode != "home" && mode != "new_tab" && mode != "custom") mode = "home";
            settings.StartupMode = mode;
            Uri custom;
            if (!TryNormalizeWebUrl(settings.CustomStartupUrl, out custom) ||
                custom.Scheme != Uri.UriSchemeHttps)
            {
                settings.CustomStartupUrl = "https://talktoai.org/zero-browser/";
            }
            else
            {
                settings.CustomStartupUrl = custom.AbsoluteUri;
            }
            string downloads = settings.DownloadDirectory;
            if (String.IsNullOrWhiteSpace(downloads) || downloads.IndexOf('"') >= 0)
            {
                downloads = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Downloads"
                );
            }
            settings.DownloadDirectory = Path.GetFullPath(downloads);
            settings.SearchEngine = BrowserSearchProviders.NormalizeKey(settings.SearchEngine);
            settings.Theme = BrowserThemePalette.NormalizeTheme(settings.Theme);
            settings.AccentColor = BrowserThemePalette.NormalizeAccent(settings.AccentColor);
            settings.PasswordNeverSaveOrigins =
                BrowserCredentialWorkflowPolicy.NormalizeNeverSaveOrigins(
                    settings.PasswordNeverSaveOrigins
                );
        }

        private static bool AddressSuggestionMatches(string url, string term)
        {
            if (term.Length == 0) return true;
            string lowered = term.ToLowerInvariant();
            return url.IndexOf(lowered, StringComparison.OrdinalIgnoreCase) >= 0 ||
                AddressSuggestionForms(url).Any(value =>
                    value.StartsWith(lowered, StringComparison.OrdinalIgnoreCase)
                );
        }

        private static IEnumerable<string> AddressSuggestionForms(string url)
        {
            Uri parsed;
            if (!TryNormalizeWebUrl(url, out parsed)) yield break;
            yield return parsed.AbsoluteUri;
            string host = parsed.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase)
                ? parsed.Host.Substring(4)
                : parsed.Host;
            string display = host + parsed.PathAndQuery;
            if (!String.IsNullOrEmpty(parsed.Fragment)) display += parsed.Fragment;
            yield return display;
        }

        private static string NormalizeTitle(string title, string fallback)
        {
            string value = String.IsNullOrWhiteSpace(title) ? fallback : title.Trim();
            value = value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            while (value.Contains("  ")) value = value.Replace("  ", " ");
            if (value.Length > 240) value = value.Substring(0, 240);
            return value;
        }

        private static string NormalizeTimestamp(string value)
        {
            DateTimeOffset parsed;
            return DateTimeOffset.TryParse(value, out parsed)
                ? parsed.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                : DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        }

        private static FileInfo GetRegularBoundedFile(string path, int maximumBytes)
        {
            FileInfo file = new FileInfo(Path.GetFullPath(path));
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("ZSEC requires a regular import file.");
            }
            if (file.Length <= 0 || file.Length > maximumBytes)
            {
                throw new InvalidDataException("The import file has an invalid size.");
            }
            return file;
        }

        private void EnsureRoot()
        {
            Directory.CreateDirectory(root);
            RejectReparseDirectory(root);
        }

        private static void RejectReparseDirectory(string path)
        {
            DirectoryInfo directory = new DirectoryInfo(path);
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("ZSEC refused a reparse-point browser data root.");
            }
        }
    }

    internal sealed class BrowserRuntimeSnapshot
    {
        internal string RuntimeVersion { get; set; }
        internal bool ShieldsExtensionLoaded { get; set; }
        internal bool DnrProbePassed { get; set; }
        internal string TrackingPrevention { get; set; }
        internal bool RuntimeUpdateAvailable { get; set; }
    }

    internal static class BrowserToolbarLayout
    {
        internal const int CompactToolbarWidth = 1120;
        internal const int StandardMinimumAddressWidth = 280;
        internal const int CompactMinimumAddressWidth = 180;

        internal static string NativeGuardLabel(bool strict, int toolbarWidth)
        {
            string mode = strict ? "Strict" : "Standard";
            return toolbarWidth < CompactToolbarWidth
                ? "Guard: " + mode
                : "Native guard: " + mode;
        }

        internal static int AddressWidth(int toolbarWidth, int fixedItemWidth)
        {
            int minimum = toolbarWidth < CompactToolbarWidth
                ? CompactMinimumAddressWidth
                : StandardMinimumAddressWidth;
            return Math.Max(minimum, toolbarWidth - Math.Max(0, fixedItemWidth));
        }
    }
}
