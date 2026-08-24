using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserMigrationProfile
    {
        public string Browser { get; set; }
        public string Name { get; set; }
        public string Root { get; set; }
        public string BookmarkPath { get; set; }
        public string HistoryPath { get; set; }
        public string SessionPath { get; set; }
        public string HistoryBoundary { get; set; }
        public string PasswordBoundary { get; set; }
        public string DisplayName { get { return Browser + " - " + Name; } }
    }

    internal sealed class BrowserMigrationItem
    {
        public string Kind { get; set; }
        public string Title { get; set; }
        public string Url { get; set; }
    }

    internal sealed class BrowserMigrationPlan
    {
        public BrowserMigrationProfile Profile { get; set; }
        public List<BrowserMigrationItem> Items { get; set; }
        public int DuplicateCount { get; set; }
        public string SessionBoundary { get; set; }
        public string HistoryBoundary { get; set; }
        public string PasswordBoundary { get; set; }
        public int BookmarkCount { get { return Items.Count(item => item.Kind == "bookmark"); } }
        public int HistoryCount { get { return Items.Count(item => item.Kind == "history"); } }
        public int TabCount { get { return Items.Count(item => item.Kind == "tab"); } }
    }

    internal static class BrowserMigrationPolicy
    {
        internal const int MaximumSourceBytes = 32 * 1024 * 1024;
        internal const int MaximumCandidates = 2000;

        internal static List<BrowserMigrationProfile> DiscoverInstalledProfiles()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            List<BrowserMigrationProfile> result = new List<BrowserMigrationProfile>();
            AddChromiumProfiles(result, "Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"));
            AddChromiumProfiles(result, "Chrome", Path.Combine(local, "Google", "Chrome", "User Data"));
            AddChromiumProfiles(result, "Edge", Path.Combine(local, "Microsoft", "Edge", "User Data"));
            AddFirefoxProfiles(result, Path.Combine(roaming, "Mozilla", "Firefox"));
            return result.OrderBy(item => item.Browser).ThenBy(item => item.Name).ToList();
        }

        internal static BrowserMigrationPlan Preview(
            BrowserMigrationProfile profile, IEnumerable<BrowserBookmark> existing)
        {
            if (profile == null) throw new ArgumentNullException("profile");
            Dictionary<string, HashSet<string>> seen = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
            {
                { "bookmark", new HashSet<string>(StringComparer.OrdinalIgnoreCase) },
                { "history", new HashSet<string>(StringComparer.OrdinalIgnoreCase) },
                { "tab", new HashSet<string>(StringComparer.OrdinalIgnoreCase) }
            };
            foreach (BrowserBookmark bookmark in existing ?? new List<BrowserBookmark>())
                if (bookmark != null && !String.IsNullOrWhiteSpace(bookmark.Url)) seen["bookmark"].Add(bookmark.Url);
            BrowserMigrationPlan plan = new BrowserMigrationPlan
            {
                Profile = profile,
                Items = new List<BrowserMigrationItem>(),
                HistoryBoundary = profile.HistoryBoundary ??
                    "History is not available from this profile through a reviewed, read-only format.",
                PasswordBoundary = profile.PasswordBoundary ??
                    "Passwords require an explicit CSV export from the source browser; encrypted browser databases are never decrypted or copied.",
                SessionBoundary = profile.Browser == "Firefox"
                    ? "Only web URLs from a readable recovery session are offered; cookies, form data and authentication tokens are never copied."
                    : "Open-tab import is unavailable for this Chromium profile because its session format cannot be read here without unsafe state handling. Use the source browser's Bookmark all tabs command, then import bookmarks."
            };
            foreach (BrowserMigrationItem candidate in ReadBookmarks(profile)
                .Concat(ReadPortableHistory(profile))
                .Concat(ReadSafeSessionUrls(profile)))
            {
                Uri parsed;
                if (!BrowserDataStore.TryNormalizeWebUrl(candidate.Url, out parsed)) continue;
                string normalized = parsed.AbsoluteUri;
                HashSet<string> kindSeen;
                if (!seen.TryGetValue(candidate.Kind ?? String.Empty, out kindSeen)) continue;
                if (!kindSeen.Add(normalized)) { plan.DuplicateCount++; continue; }
                candidate.Url = normalized;
                if (String.IsNullOrWhiteSpace(candidate.Title)) candidate.Title = parsed.Host;
                plan.Items.Add(candidate);
                if (plan.Items.Count >= MaximumCandidates) break;
            }
            return plan;
        }

        internal static int ImportBookmarks(BrowserDataStore store, BrowserProductData data, BrowserMigrationPlan plan)
        {
            if (store == null || data == null || plan == null) throw new ArgumentNullException("plan");
            int added = 0;
            foreach (BrowserMigrationItem item in plan.Items.Where(item => item.Kind == "bookmark"))
            {
                if (data.Bookmarks.Count >= BrowserDataStore.MaximumBookmarks) break;
                if (store.AddBookmark(data, item.Title, item.Url)) added++;
            }
            return added;
        }

        internal static int ImportHistory(BrowserDataStore store, BrowserProductData data, BrowserMigrationPlan plan)
        {
            if (store == null || data == null || plan == null) throw new ArgumentNullException("plan");
            if (!data.Settings.RecordHistory) return 0;
            HashSet<string> existing = new HashSet<string>(
                data.History.Where(item => item != null).Select(item => item.Url),
                StringComparer.OrdinalIgnoreCase
            );
            int added = 0;
            foreach (BrowserMigrationItem item in plan.Items.Where(item => item.Kind == "history"))
            {
                if (data.History.Count >= BrowserDataStore.MaximumHistoryEntries) break;
                if (!existing.Add(item.Url)) continue;
                store.AddHistory(data, item.Title, item.Url, false);
                added++;
            }
            return added;
        }

        private static void AddChromiumProfiles(List<BrowserMigrationProfile> result, string browser, string userData)
        {
            if (!Directory.Exists(userData) || IsReparse(userData)) return;
            foreach (string root in Directory.GetDirectories(userData))
            {
                if (IsReparse(root)) continue;
                string name = Path.GetFileName(root);
                if (!(name == "Default" || name.StartsWith("Profile ", StringComparison.Ordinal))) continue;
                string bookmarks = Path.Combine(root, "Bookmarks");
                string history = Path.Combine(root, "History");
                string sessions = Path.Combine(root, "Sessions");
                if (!File.Exists(bookmarks) && !File.Exists(history) && !Directory.Exists(sessions)) continue;
                result.Add(new BrowserMigrationProfile
                {
                    Browser = browser,
                    Name = name,
                    Root = root,
                    BookmarkPath = File.Exists(bookmarks) && !IsReparse(bookmarks) ? bookmarks : null,
                    HistoryPath = File.Exists(history) && !IsReparse(history) ? history : null,
                    SessionPath = Directory.Exists(sessions) && !IsReparse(sessions) ? sessions : null,
                    HistoryBoundary = "This profile stores history in a live Chromium SQLite database. ZSEC does not copy or query the live database; export history to a reviewed JSON file first.",
                    PasswordBoundary = "Use the source browser's password manager to export CSV, then import it in ZSEC Passwords. The encrypted Login Data database is never decrypted or copied."
                });
            }
        }

        private static void AddFirefoxProfiles(List<BrowserMigrationProfile> result, string firefoxRoot)
        {
            string profiles = Path.Combine(firefoxRoot, "Profiles");
            if (!Directory.Exists(profiles) || IsReparse(profiles)) return;
            foreach (string root in Directory.GetDirectories(profiles))
            {
                if (IsReparse(root)) continue;
                string backupRoot = Path.Combine(root, "bookmarkbackups");
                string bookmark = Directory.Exists(backupRoot)
                    ? Directory.GetFiles(backupRoot, "*.json").OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault()
                    : null;
                string session = new[] { Path.Combine(root, "sessionstore.json"), Path.Combine(root, "sessionstore-backups", "recovery.json") }
                    .FirstOrDefault(File.Exists);
                string places = Path.Combine(root, "places.sqlite");
                if (bookmark == null && session == null && !File.Exists(places)) continue;
                result.Add(new BrowserMigrationProfile
                {
                    Browser = "Firefox", Name = Path.GetFileName(root), Root = root,
                    BookmarkPath = bookmark, SessionPath = session,
                    HistoryPath = File.Exists(places) && !IsReparse(places) ? places : null,
                    HistoryBoundary = "This profile stores history in a live Firefox places.sqlite database. ZSEC does not copy or query the live database; export history to a reviewed JSON file first.",
                    PasswordBoundary = "Use Firefox Passwords to export CSV, then import it in ZSEC Passwords. logins.json and key4.db are never decrypted or copied."
                });
            }
        }

        private static IEnumerable<BrowserMigrationItem> ReadBookmarks(BrowserMigrationProfile profile)
        {
            if (String.IsNullOrWhiteSpace(profile.BookmarkPath)) return new List<BrowserMigrationItem>();
            object root = ReadJson(profile.BookmarkPath);
            List<BrowserMigrationItem> items = new List<BrowserMigrationItem>();
            Walk(root, items, "bookmark", profile.Browser == "Firefox");
            return items;
        }

        private static IEnumerable<BrowserMigrationItem> ReadSafeSessionUrls(BrowserMigrationProfile profile)
        {
            if (profile.Browser != "Firefox" || String.IsNullOrWhiteSpace(profile.SessionPath))
                return new List<BrowserMigrationItem>();
            List<BrowserMigrationItem> items = new List<BrowserMigrationItem>();
            object root = ReadJson(profile.SessionPath);
            IDictionary<string, object> rootMap = root as IDictionary<string, object>;
            object windowsValue;
            object[] windows = rootMap != null && rootMap.TryGetValue("windows", out windowsValue)
                ? windowsValue as object[] : null;
            if (windows == null) return items;
            foreach (object windowValue in windows)
            {
                IDictionary<string, object> window = windowValue as IDictionary<string, object>;
                object tabsValue;
                object[] tabs = window != null && window.TryGetValue("tabs", out tabsValue)
                    ? tabsValue as object[] : null;
                if (tabs == null) continue;
                foreach (object tabValue in tabs)
                {
                    IDictionary<string, object> tab = tabValue as IDictionary<string, object>;
                    object entriesValue;
                    object[] entries = tab != null && tab.TryGetValue("entries", out entriesValue)
                        ? entriesValue as object[] : null;
                    if (entries == null || entries.Length == 0) continue;
                    int selected = entries.Length - 1;
                    object indexValue;
                    int index;
                    if (tab.TryGetValue("index", out indexValue) && Int32.TryParse(Convert.ToString(indexValue), out index))
                        selected = Math.Max(0, Math.Min(entries.Length - 1, index - 1));
                    IDictionary<string, object> entry = entries[selected] as IDictionary<string, object>;
                    object urlValue;
                    if (entry == null || !entry.TryGetValue("url", out urlValue)) continue;
                    object titleValue;
                    entry.TryGetValue("title", out titleValue);
                    items.Add(new BrowserMigrationItem { Kind = "tab", Title = titleValue as string, Url = urlValue as string });
                    if (items.Count >= MaximumCandidates) return items;
                }
            }
            return items;
        }

        private static IEnumerable<BrowserMigrationItem> ReadPortableHistory(BrowserMigrationProfile profile)
        {
            // Live Chromium/Firefox history stores are SQLite databases which may be
            // locked and contain more state than URLs. Only an explicitly assigned,
            // regular JSON export is accepted by this policy layer.
            if (String.IsNullOrWhiteSpace(profile.HistoryPath) ||
                !String.Equals(Path.GetExtension(profile.HistoryPath), ".json", StringComparison.OrdinalIgnoreCase))
                return new List<BrowserMigrationItem>();
            object root = ReadJson(profile.HistoryPath);
            List<BrowserMigrationItem> items = new List<BrowserMigrationItem>();
            Walk(root, items, "history", false);
            return items;
        }

        private static object ReadJson(string path)
        {
            FileInfo file = new FileInfo(Path.GetFullPath(path));
            if (!file.Exists || IsReparse(file.FullName) || file.Length <= 0 || file.Length > MaximumSourceBytes)
                throw new InvalidDataException("Migration source is absent, linked or outside the size limit.");
            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = MaximumSourceBytes, RecursionLimit = 256 };
            return serializer.DeserializeObject(File.ReadAllText(file.FullName, Encoding.UTF8));
        }

        private static void Walk(object node, List<BrowserMigrationItem> items, string kind, bool firefox)
        {
            if (node == null || items.Count >= MaximumCandidates) return;
            IDictionary<string, object> map = node as IDictionary<string, object>;
            if (map != null)
            {
                object urlValue;
                string url = null;
                if (map.TryGetValue("url", out urlValue)) url = urlValue as string;
                if (firefox && map.TryGetValue("uri", out urlValue)) url = urlValue as string;
                if (!String.IsNullOrWhiteSpace(url))
                {
                    object titleValue;
                    map.TryGetValue("name", out titleValue);
                    if (titleValue == null) map.TryGetValue("title", out titleValue);
                    items.Add(new BrowserMigrationItem { Kind = kind, Title = titleValue as string, Url = url });
                }
                foreach (object child in map.Values) Walk(child, items, kind, firefox);
                return;
            }
            object[] array = node as object[];
            if (array != null) foreach (object child in array) Walk(child, items, kind, firefox);
        }

        private static bool IsReparse(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
    }
}
