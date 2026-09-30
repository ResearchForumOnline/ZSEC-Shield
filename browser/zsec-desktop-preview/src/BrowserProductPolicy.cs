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

    // Kept in parity with zeroq-shields/src/login-compatibility.js. Only
    // functional resources receive tracker-list exceptions; strict guard remains.
    internal static class BrowserLoginCompatibility
    {
        private sealed class Group
        {
            internal string[] Sites, Hosts, CdnDomains;
            internal Group(string[] sites, string[] hosts, string[] cdn)
            { Sites = sites; Hosts = hosts; CdnDomains = cdn; }
        }
        private static readonly Group[] Groups =
        {
            new Group(new[] { "google.com" }, new[] { "google.com", "www.google.com", "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com", "gemini.google.com", "myaccount.google.com", "apis.google.com", "www.googleapis.com", "oauth2.googleapis.com", "accounts.gstatic.com", "www.gstatic.com", "ssl.gstatic.com", "fonts.gstatic.com", "fonts.googleapis.com", "lh3.googleusercontent.com" }, new string[0]),
            new Group(new[] { "chatgpt.com", "openai.com", "chat.openai.com" }, new[] { "chatgpt.com", "www.chatgpt.com", "chat.openai.com", "openai.com", "www.openai.com", "auth.openai.com", "auth0.openai.com", "platform.openai.com", "cdn.oaistatic.com", "challenges.cloudflare.com", "accounts.google.com", "appleid.apple.com", "login.live.com", "login.microsoftonline.com" }, new[] { "oaistatic.com", "oaiusercontent.com" }),
            new Group(new[] { "facebook.com", "instagram.com", "messenger.com" }, new[] { "facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com", "www.messenger.com", "messenger.com", "instagram.com", "www.instagram.com", "graph.facebook.com", "connect.facebook.net" }, new[] { "fbcdn.net", "cdninstagram.com" }),
            new Group(new[] { "microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com" }, new[] { "www.microsoft.com", "account.microsoft.com", "login.microsoftonline.com", "login.live.com", "account.live.com", "outlook.live.com", "outlook.office.com", "www.office.com", "office.com", "aadcdn.msauth.net", "aadcdn.msftauth.net", "logincdn.msauth.net" }, new string[0]),
            new Group(new[] { "github.com" }, new[] { "github.com", "www.github.com", "api.github.com", "github.githubassets.com", "avatars.githubusercontent.com", "challenges.cloudflare.com" }, new string[0]),
            new Group(new[] { "apple.com", "icloud.com" }, new[] { "appleid.apple.com", "account.apple.com", "www.apple.com", "www.icloud.com", "icloud.com", "idmsa.apple.com", "appleid.cdn-apple.com" }, new string[0])
        };
        private static readonly string[] AuthHosts =
        {
            "accounts.google.com", "auth.openai.com", "auth0.openai.com",
            "appleid.apple.com", "idmsa.apple.com", "login.live.com",
            "login.microsoftonline.com", "github.com", "www.facebook.com"
        };
        private static bool TrySecureUri(string candidate, out Uri value)
        {
            value = null;
            string origin;
            Uri parsed;
            if (!BrowserPopupPolicy.TryNormalizeOrigin(candidate, out origin) ||
                !Uri.TryCreate(candidate, UriKind.Absolute, out parsed) ||
                parsed.Port != 443) return false;
            value = parsed;
            return true;
        }
        internal static bool IsFunctionalResource(string topLevelUrl, string requestUrl)
        {
            Uri top, request;
            if (!TrySecureUri(topLevelUrl, out top) || !TrySecureUri(requestUrl, out request) ||
                BrowserRequestPolicy.IsYoutubeSite(top.Host)) return false;
            return Groups.Any(group => group.Sites.Any(site =>
                BrowserRequestPolicy.HostMatchesDomain(top.Host, site)) &&
                (group.Hosts.Contains(request.Host, StringComparer.OrdinalIgnoreCase) ||
                group.CdnDomains.Any(cdn => BrowserRequestPolicy.HostMatchesDomain(request.Host, cdn))));
        }
        internal static bool IsLoginPopup(string openerUrl, string requestedUrl)
        {
            Uri opener, target;
            if (!TrySecureUri(openerUrl, out opener) || !TrySecureUri(requestedUrl, out target) ||
                BrowserRequestPolicy.IsYoutubeSite(opener.Host)) return false;
            Group source = Groups.FirstOrDefault(group => group.Hosts.Contains(
                opener.Host, StringComparer.OrdinalIgnoreCase) && group.Sites.Any(site =>
                BrowserRequestPolicy.HostMatchesDomain(opener.Host, site)));
            if (source == null) return false;
            return AuthHosts.Contains(target.Host, StringComparer.OrdinalIgnoreCase) ||
                source.Hosts.Contains(target.Host, StringComparer.OrdinalIgnoreCase) &&
                source.Sites.Any(site => BrowserRequestPolicy.HostMatchesDomain(target.Host, site));
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
            IEnumerable<string> reviewedDomains,
            bool loginCompatibility = true
        )
        {
            Uri topLevel;
            Uri request;
            if (!TryWebUri(topLevelUrl, out topLevel) || !TryWebUri(requestUrl, out request))
            {
                return false;
            }
            if (IsSameSite(topLevel.Host, request.Host)) return false;
            if (loginCompatibility && BrowserLoginCompatibility.IsFunctionalResource(topLevelUrl, requestUrl)) return false;
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
