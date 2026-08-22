using System;
using System.IO;
using System.Linq;
using System.Text;
using TalkToAI.ZsecBrowserPreview;

internal static class BrowserProductStateTests
{
    private static int assertions;

    private static void Assert(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    public static int Main()
    {
        string parent = Path.Combine(
            Path.GetTempPath(),
            "zsec-browser-product-state-tests-" + Guid.NewGuid().ToString("N")
        );
        try
        {
            TestDefaultsAndRoundTrip(Path.Combine(parent, "roundtrip"));
            TestBookmarksAndImportExport(Path.Combine(parent, "bookmarks"));
            TestHistoryPolicyAndBounds(Path.Combine(parent, "history"));
            TestAddressSuggestionsAndSearch(Path.Combine(parent, "suggestions"));
            TestNativeRequestPolicy();
            Console.WriteLine("Browser product state tests passed: " + assertions.ToString());
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.ToString());
            return 1;
        }
        finally
        {
            if (Directory.Exists(parent)) Directory.Delete(parent, true);
        }
    }

    private static void TestDefaultsAndRoundTrip(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        Assert(data.SchemaVersion == 2, "Default schema version is wrong.");
        Assert(data.Settings.StartupMode == "home", "Default startup mode is wrong.");
        Assert(data.Settings.RecordHistory, "History should be enabled by default.");
        Assert(data.Settings.MinimizeToTray, "Minimize-to-tray should be available by default.");
        Assert(!data.Settings.CloseToTray, "The close button must default to a clean exit.");
        Assert(data.Settings.AskDownloadLocation, "Download location prompting should default on.");
        Assert(data.Settings.BlockYoutubeAds, "YouTube ad protection should default on.");
        Assert(data.Settings.SearchEngine == "brave", "Brave Search should be the default.");

        data.Settings.StartupMode = "custom";
        data.Settings.CustomStartupUrl = "https://example.com/start";
        data.Settings.NativeStrictMode = true;
        store.Save(data);
        BrowserProductData loaded = store.Load();
        Assert(loaded.Settings.StartupMode == "custom", "Startup mode did not persist.");
        Assert(loaded.Settings.CustomStartupUrl == "https://example.com/start", "Custom startup URL did not normalize.");
        Assert(loaded.Settings.NativeStrictMode, "Native strict mode did not persist.");

        loaded.Settings.CustomStartupUrl = "javascript:alert(1)";
        loaded.Settings.StartupMode = "custom";
        store.Save(loaded);
        BrowserProductData sanitized = store.Load();
        Assert(
            sanitized.Settings.CustomStartupUrl == "https://talktoai.org/zero-browser/",
            "Unsafe startup URL was not replaced."
        );
    }

    private static void TestBookmarksAndImportExport(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        Assert(store.AddBookmark(data, "Example", "https://example.com/one"), "Bookmark was not added.");
        Assert(!store.AddBookmark(data, "Updated", "https://example.com/one"), "Duplicate bookmark was added.");
        Assert(data.Bookmarks.Count == 1, "Duplicate URL should update one bookmark.");
        Assert(data.Bookmarks[0].Title == "Updated", "Duplicate bookmark title was not updated.");
        Assert(!store.AddBookmark(data, "Unsafe", "javascript:alert(1)"), "Unsafe bookmark URL was accepted.");

        Directory.CreateDirectory(root);
        string export = Path.Combine(root, "bookmarks.html");
        store.ExportBookmarksHtml(data, export);
        string exported = File.ReadAllText(export, Encoding.UTF8);
        Assert(exported.Contains("NETSCAPE-Bookmark-file-1"), "Export is not bookmark HTML.");
        Assert(exported.Contains("https://example.com/one"), "Export omitted bookmark URL.");

        string importRoot = Path.Combine(root, "imported");
        Directory.CreateDirectory(importRoot);
        string import = Path.Combine(importRoot, "input.html");
        File.WriteAllText(
            import,
            "<!doctype html><a href=\"https://example.org/a\">Alpha</a>" +
            "<a href='http://example.net/b'>Beta</a>" +
            "<a href=\"javascript:alert(1)\">Unsafe</a>",
            new UTF8Encoding(false)
        );
        BrowserDataStore importedStore = new BrowserDataStore(importRoot);
        BrowserProductData importedData = importedStore.Load();
        int count = importedStore.ImportBookmarksHtml(importedData, import);
        Assert(count == 2, "Bookmark import count is wrong.");
        Assert(importedData.Bookmarks.Count == 2, "Bookmark import did not preserve two safe URLs.");
        Assert(importedData.Bookmarks.All(item => item.Url.StartsWith("http", StringComparison.Ordinal)), "Unsafe import survived.");
        Assert(importedStore.RemoveBookmark(importedData, "https://example.org/a"), "Bookmark removal failed.");
        Assert(importedData.Bookmarks.Count == 1, "Bookmark removal count is wrong.");
    }

    private static void TestHistoryPolicyAndBounds(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        store.AddHistory(data, "Example", "https://example.com/");
        Assert(data.History.Count == 1, "History entry was not recorded.");
        store.AddHistory(data, "Typed example", "https://example.com/", true);
        Assert(data.History.Count == 1, "A repeat visit should consolidate one URL.");
        Assert(data.History[0].TypedCount == 1, "Typed navigation count was not recorded.");
        data.Settings.RecordHistory = false;
        store.AddHistory(data, "Ignored", "https://example.org/");
        Assert(data.History.Count == 1, "Disabled history still recorded an entry.");

        data.Settings.RecordHistory = true;
        data.History.Clear();
        for (int index = 0; index < BrowserDataStore.MaximumHistoryEntries + 7; index++)
        {
            data.History.Add(new BrowserHistoryEntry
            {
                Title = "Entry " + index.ToString(),
                Url = "https://example.com/" + index.ToString(),
                VisitedAtUtc = "2026-08-22T00:00:00Z"
            });
        }
        store.Save(data);
        BrowserProductData bounded = store.Load();
        Assert(
            bounded.History.Count == BrowserDataStore.MaximumHistoryEntries,
            "History bound was not enforced."
        );
        store.ClearHistory(bounded);
        Assert(store.Load().History.Count == 0, "History clear did not persist.");
    }

    private static void TestAddressSuggestionsAndSearch(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        store.AddHistory(data, "Ordinary", "https://ordinary.example/path", false);
        store.AddHistory(data, "Typed", "https://www.typed.example/article", true);
        store.AddBookmark(data, "Saved", "https://saved.example/bookmark");
        string[] suggestions = store.GetAddressSuggestions(data, String.Empty, 20).ToArray();
        Assert(suggestions[0] == "https://www.typed.example/article", "Typed URL was not ranked first.");
        Assert(suggestions.Contains("typed.example/article"), "Scheme-free typed URL suggestion is absent.");
        Assert(suggestions.Contains("saved.example/bookmark"), "Bookmark suggestion is absent.");
        Assert(
            store.GetAddressSuggestions(data, "typed", 20).All(value =>
                value.IndexOf("typed", StringComparison.OrdinalIgnoreCase) >= 0),
            "Address suggestion filtering returned an unrelated URL."
        );
        Assert(
            BrowserSearchProviders.BuildSearchUrl("duckduckgo", "free speech") ==
                "https://duckduckgo.com/?q=free%20speech",
            "DuckDuckGo search URL is wrong."
        );
        Assert(
            BrowserSearchProviders.NormalizeKey("not-a-provider") == "brave",
            "Unknown search providers must fail to the reviewed default."
        );
        Assert(BrowserSearchProviders.All.Count() == 7, "Search provider catalogue drifted.");
    }

    private static void TestNativeRequestPolicy()
    {
        const string Youtube = "https://www.youtube.com/watch?v=test";
        Assert(
            BrowserRequestPolicy.IsYoutubeAdRequest(
                Youtube,
                "https://www.youtube.com/pagead/interaction/"
            ),
            "YouTube page-ad endpoint was not classified."
        );
        Assert(
            BrowserRequestPolicy.IsYoutubeAdRequest(
                Youtube,
                "https://static.doubleclick.net/instream/ad_status.js"
            ),
            "YouTube third-party ad endpoint was not classified."
        );
        Assert(
            !BrowserRequestPolicy.IsYoutubeAdRequest(
                Youtube,
                "https://www.youtube.com/youtubei/v1/player"
            ),
            "The normal YouTube player endpoint must not be blocked."
        );
        string[] trackers = { "doubleclick.net", "tracker.example" };
        Assert(
            BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                "https://news.example/article",
                "https://ads.doubleclick.net/pixel.js",
                trackers
            ),
            "Reviewed third-party tracker was not classified."
        );
        Assert(
            !BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                "https://news.example/article",
                "https://cdn.news.example/app.js",
                trackers
            ),
            "Same-site content was incorrectly classified as a tracker."
        );
        Assert(
            !BrowserRequestPolicy.HostMatchesDomain("notdoubleclick.net", "doubleclick.net"),
            "Tracker matching crossed a DNS label boundary."
        );
    }
}
