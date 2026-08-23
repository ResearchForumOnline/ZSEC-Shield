using System;
using System.Collections.Generic;
using System.Drawing;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserThemePalette
    {
        internal string Key { get; private set; }
        internal string DisplayName { get; private set; }
        internal Color Background { get; private set; }
        internal Color Panel { get; private set; }
        internal Color Surface { get; private set; }
        internal Color Hover { get; private set; }
        internal Color Foreground { get; private set; }
        internal Color Muted { get; private set; }
        internal Color Accent { get; private set; }
        internal Color AccentSecondary { get; private set; }
        internal Color Border { get; private set; }

        private BrowserThemePalette() { }

        internal static readonly string[] ThemeKeys = { "soft_dark", "slate", "midnight" };
        internal static readonly string[] AccentKeys = { "teal", "blue", "violet", "amber" };

        internal static string NormalizeTheme(string value)
        {
            string key = (value ?? String.Empty).Trim().ToLowerInvariant();
            return Array.IndexOf(ThemeKeys, key) >= 0 ? key : "soft_dark";
        }

        internal static string NormalizeAccent(string value)
        {
            string key = (value ?? String.Empty).Trim().ToLowerInvariant();
            return Array.IndexOf(AccentKeys, key) >= 0 ? key : "teal";
        }

        internal static BrowserThemePalette Resolve(BrowserSettings settings)
        {
            string theme = NormalizeTheme(settings == null ? null : settings.Theme);
            string accentKey = NormalizeAccent(settings == null ? null : settings.AccentColor);
            Color background;
            Color panel;
            Color surface;
            Color hover;
            string name;
            if (theme == "slate")
            {
                background = Color.FromArgb(31, 38, 48);
                panel = Color.FromArgb(39, 48, 60);
                surface = Color.FromArgb(49, 60, 74);
                hover = Color.FromArgb(61, 74, 91);
                name = "Slate";
            }
            else if (theme == "midnight")
            {
                background = Color.FromArgb(14, 23, 35);
                panel = Color.FromArgb(20, 32, 47);
                surface = Color.FromArgb(29, 43, 60);
                hover = Color.FromArgb(39, 57, 77);
                name = "Midnight blue";
            }
            else
            {
                background = Color.FromArgb(24, 32, 40);
                panel = Color.FromArgb(31, 42, 52);
                surface = Color.FromArgb(40, 53, 65);
                hover = Color.FromArgb(52, 68, 82);
                name = "Soft dark";
            }
            Color accent = accentKey == "blue" ? Color.FromArgb(83, 181, 255)
                : accentKey == "violet" ? Color.FromArgb(184, 151, 255)
                : accentKey == "amber" ? Color.FromArgb(255, 193, 92)
                : Color.FromArgb(57, 220, 190);
            return new BrowserThemePalette
            {
                Key = theme,
                DisplayName = name,
                Background = background,
                Panel = panel,
                Surface = surface,
                Hover = hover,
                Foreground = Color.FromArgb(241, 245, 249),
                Muted = Color.FromArgb(184, 197, 208),
                Accent = accent,
                AccentSecondary = Color.FromArgb(106, 190, 255),
                Border = Color.FromArgb(91, 110, 126)
            };
        }

        internal static string ThemeDisplayName(string key)
        {
            return Resolve(new BrowserSettings { Theme = key, AccentColor = "teal" }).DisplayName;
        }

        internal static string AccentDisplayName(string key)
        {
            string normalized = NormalizeAccent(key);
            return Char.ToUpperInvariant(normalized[0]) + normalized.Substring(1);
        }
    }
}
