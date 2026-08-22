using System;
using System.Collections.Generic;
using System.Linq;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserSearchProvider
    {
        public string Key { get; private set; }
        public string Name { get; private set; }
        public string SearchTemplate { get; private set; }

        internal BrowserSearchProvider(string key, string name, string searchTemplate)
        {
            Key = key;
            Name = name;
            SearchTemplate = searchTemplate;
        }
    }

    internal static class BrowserSearchProviders
    {
        private static readonly BrowserSearchProvider[] Providers =
        {
            new BrowserSearchProvider("brave", "Brave Search", "https://search.brave.com/search?q={0}"),
            new BrowserSearchProvider("duckduckgo", "DuckDuckGo", "https://duckduckgo.com/?q={0}"),
            new BrowserSearchProvider("startpage", "Startpage", "https://www.startpage.com/sp/search?query={0}"),
            new BrowserSearchProvider("qwant", "Qwant", "https://www.qwant.com/?q={0}"),
            new BrowserSearchProvider("ecosia", "Ecosia", "https://www.ecosia.org/search?q={0}"),
            new BrowserSearchProvider("bing", "Microsoft Bing", "https://www.bing.com/search?q={0}"),
            new BrowserSearchProvider("google", "Google", "https://www.google.com/search?q={0}")
        };

        internal static IEnumerable<BrowserSearchProvider> All
        {
            get { return Providers; }
        }

        internal static string NormalizeKey(string candidate)
        {
            BrowserSearchProvider provider = Providers.FirstOrDefault(item =>
                String.Equals(item.Key, candidate, StringComparison.OrdinalIgnoreCase)
            );
            return provider == null ? "brave" : provider.Key;
        }

        internal static string DisplayName(string key)
        {
            string normalized = NormalizeKey(key);
            return Providers.First(item => item.Key == normalized).Name;
        }

        internal static string BuildSearchUrl(string key, string query)
        {
            string normalized = NormalizeKey(key);
            BrowserSearchProvider provider = Providers.First(item => item.Key == normalized);
            return String.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                provider.SearchTemplate,
                Uri.EscapeDataString(query ?? String.Empty)
            );
        }
    }

    internal static class BrowserRequestPolicy
    {
        private static readonly string[] YoutubeAdHosts =
        {
            "ad.doubleclick.net",
            "googleads.g.doubleclick.net",
            "pubads.g.doubleclick.net",
            "securepubads.g.doubleclick.net",
            "static.doubleclick.net",
            "survey.g.doubleclick.net",
            "googleadservices.com",
            "www.googleadservices.com"
        };

        private static readonly string[] YoutubeAdPathPrefixes =
        {
            "/pagead/",
            "/youtubei/v1/player/ad_break",
            "/get_midroll_",
            "/api/stats/ads",
            "/ptracking",
            "/pagead/conversion"
        };

        internal static bool IsYoutubeSite(string host)
        {
            return HostMatchesDomain(host, "youtube.com") ||
                HostMatchesDomain(host, "youtube-nocookie.com");
        }

        internal static bool IsYoutubeAdRequest(string topLevelUrl, string requestUrl)
        {
            Uri topLevel;
            Uri request;
            if (!TryWebUri(topLevelUrl, out topLevel) || !TryWebUri(requestUrl, out request))
            {
                return false;
            }
            if (!IsYoutubeSite(topLevel.Host)) return false;
            if (YoutubeAdHosts.Any(host => HostMatchesDomain(request.Host, host))) return true;
            if (!IsYoutubeSite(request.Host)) return false;
            string path = request.AbsolutePath;
            return YoutubeAdPathPrefixes.Any(prefix =>
                path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            );
        }

        internal static bool IsReviewedThirdPartyTracker(
            string topLevelUrl,
            string requestUrl,
            IEnumerable<string> reviewedDomains
        )
        {
            Uri topLevel;
            Uri request;
            if (!TryWebUri(topLevelUrl, out topLevel) || !TryWebUri(requestUrl, out request))
            {
                return false;
            }
            if (IsSameSite(topLevel.Host, request.Host)) return false;
            return reviewedDomains != null && reviewedDomains.Any(domain =>
                HostMatchesDomain(request.Host, domain)
            );
        }

        internal static bool HostMatchesDomain(string host, string domain)
        {
            string normalizedHost = (host ?? String.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            string normalizedDomain = (domain ?? String.Empty).Trim().Trim('.').ToLowerInvariant();
            if (normalizedHost.Length == 0 || normalizedDomain.Length == 0) return false;
            return normalizedHost == normalizedDomain ||
                normalizedHost.EndsWith("." + normalizedDomain, StringComparison.Ordinal);
        }

        private static bool IsSameSite(string first, string second)
        {
            string a = (first ?? String.Empty).TrimEnd('.').ToLowerInvariant();
            string b = (second ?? String.Empty).TrimEnd('.').ToLowerInvariant();
            return a == b || a.EndsWith("." + b, StringComparison.Ordinal) ||
                b.EndsWith("." + a, StringComparison.Ordinal);
        }

        private static bool TryWebUri(string candidate, out Uri uri)
        {
            uri = null;
            Uri parsed;
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out parsed)) return false;
            if (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp)
            {
                return false;
            }
            if (String.IsNullOrWhiteSpace(parsed.Host)) return false;
            uri = parsed;
            return true;
        }
    }
}
