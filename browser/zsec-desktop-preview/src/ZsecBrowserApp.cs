using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

[assembly: AssemblyTitle("ZSEC Browser Desktop Preview")]
[assembly: AssemblyDescription("Hardened Windows browser shell powered by Microsoft Edge WebView2")]
[assembly: AssemblyCompany("TalkToAI")]
[assembly: AssemblyProduct("ZSEC Browser")]
[assembly: AssemblyCopyright("Copyright 2026 TalkToAI")]
[assembly: AssemblyVersion("0.2.3.0")]
[assembly: AssemblyFileVersion("0.2.3.0")]
[assembly: AssemblyInformationalVersion("0.2.3-preview")]

namespace TalkToAI.ZsecBrowserPreview
{
    internal static class Program
    {
        internal const string ProductName = "ZSEC Browser";
        internal const string ProductVersion = "0.2.3";
        internal const string DefaultStartPage = "https://talktoai.org/zero-browser/";

        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string destination = ResolveDestination(args);
            try
            {
                Application.Run(new BrowserWindow(destination));
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "ZSEC Browser could not start.\r\n\r\n" + exception.Message,
                    ProductName + " Desktop Preview",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        internal static string ResolveDestination(string[] args)
        {
            string candidate = args.FirstOrDefault(value =>
                !String.IsNullOrWhiteSpace(value) && !value.StartsWith("--", StringComparison.Ordinal)
            );
            if (String.IsNullOrWhiteSpace(candidate))
            {
                return DefaultStartPage;
            }

            Uri uri;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out uri) &&
                (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
            {
                return uri.AbsoluteUri;
            }

            if (candidate.IndexOf(' ') < 0 && candidate.IndexOf('.') > 0 &&
                Uri.TryCreate("https://" + candidate, UriKind.Absolute, out uri))
            {
                return uri.AbsoluteUri;
            }

            return "https://search.brave.com/search?q=" + Uri.EscapeDataString(candidate);
        }
    }

    internal sealed class BrowserWindow : Form
    {
        private static readonly Color Background = Color.FromArgb(4, 12, 18);
        private static readonly Color PanelBackground = Color.FromArgb(9, 24, 31);
        private static readonly Color Accent = Color.FromArgb(0, 229, 170);
        private static readonly Color AccentBlue = Color.FromArgb(35, 174, 232);
        private static readonly Color Muted = Color.FromArgb(151, 170, 181);
        private static readonly string[] ActiveHighRiskContexts =
        {
            "Script", "Document", "Stylesheet", "XmlHttpRequest", "Fetch", "WebSocket"
        };

        private readonly string initialDestination;
        private readonly string applicationRoot;
        private readonly string productRoot;
        private readonly string profileRoot;
        private readonly string policyRoot;
        private readonly HashSet<string> trackerDomains;
        private readonly HashSet<string> trackingParameters;
        private readonly List<WebView2> browserViews;
        private readonly TabControl tabs;
        private readonly TextBox address;
        private readonly Label shieldStatus;
        private readonly Label runtimeStatus;
        private readonly ToolStripButton highRiskButton;
        private readonly ToolStripLabel blockedLabel;
        private CoreWebView2Environment environment;
        private int blockedRequestCount;
        private int trackingCleanupCount;
        private bool highRiskMode;
        private bool lastNavigationHttps;

        internal BrowserWindow(string destination)
        {
            initialDestination = destination;
            applicationRoot = AppDomain.CurrentDomain.BaseDirectory;
            productRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "TalkToAI",
                "ZSEC Browser"
            );
            profileRoot = Path.Combine(productRoot, "User Data");
            policyRoot = Path.Combine(applicationRoot, "policy");
            trackerDomains = LoadRequiredLines(Path.Combine(policyRoot, "tracker-domains.txt"));
            trackingParameters = LoadRequiredLines(Path.Combine(policyRoot, "tracking-parameters.txt"));
            browserViews = new List<WebView2>();

            Text = "ZSEC Browser Desktop Preview";
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            StartPosition = FormStartPosition.CenterScreen;
            WindowState = FormWindowState.Maximized;
            MinimumSize = new Size(960, 640);
            BackColor = Background;
            ForeColor = Color.White;
            KeyPreview = true;

            Panel brandBar = new Panel();
            brandBar.Dock = DockStyle.Top;
            brandBar.Height = 48;
            brandBar.BackColor = Background;

            Label brand = new Label();
            brand.Text = "ZSEC";
            brand.Font = new Font("Segoe UI Semibold", 17F, FontStyle.Bold);
            brand.ForeColor = Accent;
            brand.AutoSize = true;
            brand.Location = new Point(18, 9);
            brandBar.Controls.Add(brand);

            Label product = new Label();
            product.Text = "BROWSER";
            product.Font = new Font("Segoe UI", 11F, FontStyle.Regular);
            product.ForeColor = AccentBlue;
            product.AutoSize = true;
            product.Location = new Point(84, 16);
            brandBar.Controls.Add(product);

            Label preview = new Label();
            preview.Text = "DESKTOP PREVIEW";
            preview.Font = new Font("Segoe UI", 8F, FontStyle.Bold);
            preview.ForeColor = Muted;
            preview.AutoSize = true;
            preview.Location = new Point(178, 18);
            brandBar.Controls.Add(preview);

            shieldStatus = new Label();
            shieldStatus.Text = "  SHIELDS ACTIVE  ";
            shieldStatus.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            shieldStatus.ForeColor = Background;
            shieldStatus.BackColor = Accent;
            shieldStatus.AutoSize = true;
            shieldStatus.Padding = new Padding(4, 5, 4, 5);
            shieldStatus.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            shieldStatus.Location = new Point(ClientSize.Width - 154, 8);
            brandBar.Controls.Add(shieldStatus);
            brandBar.Resize += delegate
            {
                shieldStatus.Location = new Point(brandBar.ClientSize.Width - shieldStatus.Width - 18, 8);
            };

            ToolStrip navigation = new ToolStrip();
            navigation.Dock = DockStyle.Top;
            navigation.GripStyle = ToolStripGripStyle.Hidden;
            navigation.RenderMode = ToolStripRenderMode.System;
            navigation.BackColor = PanelBackground;
            navigation.ForeColor = Color.White;
            navigation.Padding = new Padding(10, 6, 10, 6);
            navigation.ImageScalingSize = new Size(20, 20);

            ToolStripButton backButton = CreateButton("Back", delegate { if (ActiveView != null && ActiveView.CanGoBack) ActiveView.GoBack(); });
            ToolStripButton forwardButton = CreateButton("Forward", delegate { if (ActiveView != null && ActiveView.CanGoForward) ActiveView.GoForward(); });
            ToolStripButton reloadButton = CreateButton("Reload", delegate { if (ActiveView != null) ActiveView.Reload(); });
            ToolStripButton homeButton = CreateButton("Home", delegate { Navigate(Program.DefaultStartPage); });
            ToolStripButton newTabButton = CreateButton("New tab", async delegate { await CreateTab(Program.DefaultStartPage, true); });

            address = new TextBox();
            address.BorderStyle = BorderStyle.FixedSingle;
            address.BackColor = Color.FromArgb(240, 246, 248);
            address.ForeColor = Color.FromArgb(15, 28, 34);
            address.Font = new Font("Segoe UI", 10F);
            address.Margin = new Padding(7, 3, 7, 3);
            address.Width = 660;
            address.KeyDown += AddressKeyDown;
            ToolStripControlHost addressHost = new ToolStripControlHost(address);
            addressHost.AutoSize = false;
            addressHost.Width = 660;

            highRiskButton = CreateButton("High-Risk: OFF", ToggleHighRiskMode);
            highRiskButton.CheckOnClick = false;
            ToolStripButton aboutButton = CreateButton("About", ShowAbout);

            navigation.Items.AddRange(new ToolStripItem[]
            {
                backButton,
                forwardButton,
                reloadButton,
                homeButton,
                new ToolStripSeparator(),
                addressHost,
                new ToolStripSeparator(),
                highRiskButton,
                aboutButton
            });
            navigation.Resize += delegate
            {
                int reserved = 520;
                addressHost.Width = Math.Max(260, navigation.ClientSize.Width - reserved);
            };

            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.Font = new Font("Segoe UI", 9F);
            tabs.SelectedIndexChanged += delegate { UpdateAddressFromActiveView(); };

            StatusStrip status = new StatusStrip();
            status.BackColor = PanelBackground;
            status.ForeColor = Muted;
            runtimeStatus = new Label();
            runtimeStatus.Text = "Starting Microsoft Chromium runtime...";
            runtimeStatus.ForeColor = Muted;
            runtimeStatus.AutoSize = true;
            ToolStripControlHost runtimeHost = new ToolStripControlHost(runtimeStatus);
            blockedLabel = new ToolStripLabel("Blocked: 0");
            blockedLabel.ForeColor = Accent;
            ToolStripStatusLabel spacer = new ToolStripStatusLabel();
            spacer.Spring = true;
            status.Items.Add(runtimeHost);
            status.Items.Add(spacer);
            status.Items.Add(blockedLabel);
            status.Items.Add(new ToolStripStatusLabel("Profile: isolated"));

            Controls.Add(tabs);
            Controls.Add(status);
            Controls.Add(navigation);
            Controls.Add(brandBar);

            Load += InitializeBrowserAsync;
            FormClosed += DisposeBrowserViews;
            KeyDown += BrowserKeyDown;
        }

        private WebView2 ActiveView
        {
            get
            {
                if (tabs.SelectedTab == null || tabs.SelectedTab.Controls.Count == 0)
                {
                    return null;
                }
                return tabs.SelectedTab.Controls[0] as WebView2;
            }
        }

        private ToolStripButton CreateButton(string text, EventHandler handler)
        {
            ToolStripButton button = new ToolStripButton(text);
            button.DisplayStyle = ToolStripItemDisplayStyle.Text;
            button.ForeColor = Color.White;
            button.Font = new Font("Segoe UI Semibold", 9F);
            button.Click += handler;
            return button;
        }

        private async void InitializeBrowserAsync(object sender, EventArgs args)
        {
            try
            {
                Directory.CreateDirectory(productRoot);
                Directory.CreateDirectory(profileRoot);
                RejectReparseDirectory(productRoot);
                RejectReparseDirectory(profileRoot);

                CoreWebView2EnvironmentOptions options = new CoreWebView2EnvironmentOptions();
                options.AdditionalBrowserArguments = "--enable-features=HttpsUpgrades";
                environment = await CoreWebView2Environment.CreateAsync(null, profileRoot, options);
                string runtimeVersion = CoreWebView2Environment.GetAvailableBrowserVersionString();
                runtimeStatus.Text = "Microsoft Chromium runtime " + runtimeVersion;
                await CreateTab(initialDestination, true);
                WriteRuntimeEvidence(runtimeVersion);
            }
            catch (Exception exception)
            {
                runtimeStatus.Text = "Protection unavailable";
                shieldStatus.Text = "  STARTUP FAILED  ";
                shieldStatus.BackColor = Color.FromArgb(232, 73, 78);
                MessageBox.Show(
                    "ZSEC Browser failed closed before navigation.\r\n\r\n" + exception.Message,
                    "ZSEC Browser Desktop Preview",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                Close();
            }
        }

        private async Task CreateTab(string destination, bool select)
        {
            if (environment == null)
            {
                return;
            }

            TabPage page = new TabPage("New tab");
            page.BackColor = Background;
            WebView2 view = new WebView2();
            view.Dock = DockStyle.Fill;
            view.CreationProperties = new CoreWebView2CreationProperties();
            page.Controls.Add(view);
            tabs.TabPages.Add(page);
            browserViews.Add(view);
            if (select)
            {
                tabs.SelectedTab = page;
            }

            await view.EnsureCoreWebView2Async(environment);
            ConfigureWebView(view, page);
            NavigateView(view, destination);
        }

        private void ConfigureWebView(WebView2 view, TabPage page)
        {
            CoreWebView2 core = view.CoreWebView2;
            CoreWebView2Settings settings = core.Settings;
            settings.AreHostObjectsAllowed = false;
            settings.IsWebMessageEnabled = false;
            settings.IsPasswordAutosaveEnabled = false;
            settings.IsGeneralAutofillEnabled = false;
            settings.AreDefaultScriptDialogsEnabled = false;
            settings.AreDevToolsEnabled = false;
            settings.IsStatusBarEnabled = true;
            settings.AreDefaultContextMenusEnabled = true;

            core.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            core.NavigationStarting += delegate(object sender, CoreWebView2NavigationStartingEventArgs args)
            {
                HandleNavigationStarting(view, args);
            };
            core.FrameNavigationStarting += delegate(object sender, CoreWebView2NavigationStartingEventArgs args)
            {
                if (!IsAllowedWebUri(args.Uri, false)) args.Cancel = true;
            };
            core.SourceChanged += delegate
            {
                if (view == ActiveView) address.Text = view.Source.ToString();
            };
            core.DocumentTitleChanged += delegate
            {
                string title = core.DocumentTitle;
                page.Text = String.IsNullOrWhiteSpace(title) ? "New tab" : Truncate(title, 28);
                if (view == ActiveView) Text = page.Text + " - ZSEC Browser Preview";
            };
            core.NavigationCompleted += delegate
            {
                lastNavigationHttps = view.Source != null &&
                    String.Equals(view.Source.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            };
            core.NewWindowRequested += delegate(object sender, CoreWebView2NewWindowRequestedEventArgs args)
            {
                args.Handled = true;
                if (IsAllowedWebUri(args.Uri, true))
                {
                    BeginInvoke(new Action(async delegate { await CreateTab(args.Uri, true); }));
                }
            };
            core.PermissionRequested += delegate(object sender, CoreWebView2PermissionRequestedEventArgs args)
            {
                args.State = CoreWebView2PermissionState.Deny;
                args.SavesInProfile = false;
            };
            core.ServerCertificateErrorDetected += delegate(object sender, CoreWebView2ServerCertificateErrorDetectedEventArgs args)
            {
                args.Action = CoreWebView2ServerCertificateErrorAction.Cancel;
            };
            core.DownloadStarting += HandleDownloadStarting;
            core.WebResourceRequested += delegate(object sender, CoreWebView2WebResourceRequestedEventArgs args)
            {
                HandleWebResourceRequested(view, args);
            };
            core.ProcessFailed += delegate
            {
                runtimeStatus.Text = "Renderer/runtime failure detected - reload this tab";
            };
        }

        private void HandleNavigationStarting(WebView2 view, CoreWebView2NavigationStartingEventArgs args)
        {
            Uri uri;
            if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out uri))
            {
                args.Cancel = true;
                return;
            }

            if (uri.Scheme == Uri.UriSchemeHttp)
            {
                args.Cancel = true;
                if (highRiskMode)
                {
                    ShowBlockedNotice("High-Risk Browsing blocked plaintext HTTP navigation.");
                }
                else
                {
                    UriBuilder upgraded = new UriBuilder(uri);
                    upgraded.Scheme = Uri.UriSchemeHttps;
                    upgraded.Port = -1;
                    BeginInvoke(new Action(delegate { NavigateView(view, upgraded.Uri.AbsoluteUri); }));
                }
                return;
            }

            if (!IsAllowedWebUri(args.Uri, true))
            {
                args.Cancel = true;
                ShowBlockedNotice("ZSEC blocked a non-web or unsafe navigation scheme.");
                return;
            }

            string cleaned = RemoveTrackingParameters(uri);
            if (!String.Equals(cleaned, uri.AbsoluteUri, StringComparison.Ordinal))
            {
                args.Cancel = true;
                trackingCleanupCount++;
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
                BeginInvoke(new Action(delegate { NavigateView(view, cleaned); }));
            }
        }

        private void HandleWebResourceRequested(WebView2 view, CoreWebView2WebResourceRequestedEventArgs args)
        {
            Uri requestUri;
            if (!Uri.TryCreate(args.Request.Uri, UriKind.Absolute, out requestUri))
            {
                BlockRequest(args);
                return;
            }

            if (requestUri.Scheme != Uri.UriSchemeHttps && requestUri.Scheme != Uri.UriSchemeHttp)
            {
                return;
            }

            if (MatchesTrackerDomain(requestUri.Host))
            {
                BlockRequest(args);
                return;
            }

            if (highRiskMode && ActiveHighRiskContexts.Contains(args.ResourceContext.ToString()))
            {
                Uri topLevel;
                if (Uri.TryCreate(view.Source.ToString(), UriKind.Absolute, out topLevel) &&
                    !IsSameSite(topLevel.Host, requestUri.Host))
                {
                    BlockRequest(args);
                }
            }
        }

        private void BlockRequest(CoreWebView2WebResourceRequestedEventArgs args)
        {
            byte[] body = Encoding.UTF8.GetBytes("Blocked by ZSEC Browser Shields");
            args.Response = environment.CreateWebResourceResponse(
                new MemoryStream(body, false),
                403,
                "Blocked by ZSEC",
                "Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store"
            );
            blockedRequestCount++;
            blockedLabel.Text = "Blocked: " + blockedRequestCount.ToString();
            WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
        }

        private void HandleDownloadStarting(object sender, CoreWebView2DownloadStartingEventArgs args)
        {
            args.Handled = true;
            string suggestedName = SanitizeFileName(Path.GetFileName(args.ResultFilePath));
            DialogResult approval = MessageBox.Show(
                "Allow this download?\r\n\r\n" + args.DownloadOperation.Uri +
                "\r\n\r\nZSEC does not automatically open downloaded files.",
                "ZSEC download confirmation",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2
            );
            if (approval != DialogResult.Yes)
            {
                args.Cancel = true;
                return;
            }

            SaveFileDialog picker = new SaveFileDialog();
            picker.FileName = suggestedName;
            picker.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads";
            picker.OverwritePrompt = true;
            if (picker.ShowDialog(this) != DialogResult.OK)
            {
                args.Cancel = true;
                return;
            }
            args.ResultFilePath = picker.FileName;
        }

        private void AddressKeyDown(object sender, KeyEventArgs args)
        {
            if (args.KeyCode == Keys.Enter)
            {
                args.SuppressKeyPress = true;
                Navigate(Program.ResolveDestination(new[] { address.Text }));
            }
        }

        private void BrowserKeyDown(object sender, KeyEventArgs args)
        {
            if (args.Control && args.KeyCode == Keys.L)
            {
                address.Focus();
                address.SelectAll();
                args.SuppressKeyPress = true;
            }
            else if (args.Control && args.KeyCode == Keys.T)
            {
                CreateTabFromKeyboardAsync();
                args.SuppressKeyPress = true;
            }
            else if (args.Control && args.KeyCode == Keys.W && tabs.TabPages.Count > 1)
            {
                CloseActiveTab();
                args.SuppressKeyPress = true;
            }
        }

        private void Navigate(string destination)
        {
            if (ActiveView != null) NavigateView(ActiveView, destination);
        }

        private async void CreateTabFromKeyboardAsync()
        {
            await CreateTab(Program.DefaultStartPage, true);
        }

        private void NavigateView(WebView2 view, string destination)
        {
            if (!IsAllowedWebUri(destination, true))
            {
                ShowBlockedNotice("ZSEC blocked the requested address.");
                return;
            }
            view.CoreWebView2.Navigate(destination);
        }

        private void ToggleHighRiskMode(object sender, EventArgs args)
        {
            highRiskMode = !highRiskMode;
            highRiskButton.Text = highRiskMode ? "High-Risk: ON" : "High-Risk: OFF";
            highRiskButton.BackColor = highRiskMode ? Color.FromArgb(210, 74, 54) : PanelBackground;
            shieldStatus.Text = highRiskMode ? "  HIGH-RISK MODE  " : "  SHIELDS ACTIVE  ";
            shieldStatus.BackColor = highRiskMode ? Color.FromArgb(255, 179, 71) : Accent;
            WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
        }

        private void ShowAbout(object sender, EventArgs args)
        {
            string runtime = environment == null ? "not initialized" : CoreWebView2Environment.GetAvailableBrowserVersionString();
            MessageBox.Show(
                "ZSEC Browser Desktop Preview " + Program.ProductVersion + "\r\n\r\n" +
                "Engine: Microsoft Edge WebView2 (Chromium) " + runtime + "\r\n" +
                "Policy: " + trackerDomains.Count + " reviewed blocker domains\r\n" +
                "Profile: isolated under LocalAppData\r\n" +
                "Permissions: default deny\r\n" +
                "Host objects/web messaging: disabled\r\n\r\n" +
                "This is a hardened browser shell, not an independently maintained Chromium fork, " +
                "not antivirus, and not a guarantee against every exploit.",
                "About ZSEC Browser",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }

        private void CloseActiveTab()
        {
            TabPage page = tabs.SelectedTab;
            if (page == null) return;
            WebView2 view = ActiveView;
            if (view != null)
            {
                browserViews.Remove(view);
                view.Dispose();
            }
            tabs.TabPages.Remove(page);
            page.Dispose();
        }

        private void UpdateAddressFromActiveView()
        {
            if (ActiveView != null && ActiveView.Source != null)
            {
                address.Text = ActiveView.Source.ToString();
            }
        }

        private bool MatchesTrackerDomain(string host)
        {
            string normalized = host.TrimEnd('.').ToLowerInvariant();
            foreach (string domain in trackerDomains)
            {
                if (normalized == domain || normalized.EndsWith("." + domain, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool IsSameSite(string first, string second)
        {
            string a = first.TrimEnd('.').ToLowerInvariant();
            string b = second.TrimEnd('.').ToLowerInvariant();
            return a == b || a.EndsWith("." + b, StringComparison.Ordinal) || b.EndsWith("." + a, StringComparison.Ordinal);
        }

        private static bool IsAllowedWebUri(string candidate, bool allowHttp)
        {
            Uri uri;
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out uri)) return false;
            if (uri.Scheme == Uri.UriSchemeHttps) return true;
            return allowHttp && uri.Scheme == Uri.UriSchemeHttp;
        }

        private string RemoveTrackingParameters(Uri uri)
        {
            if (String.IsNullOrEmpty(uri.Query)) return uri.AbsoluteUri;
            System.Collections.Specialized.NameValueCollection query = HttpUtility.ParseQueryString(uri.Query);
            bool changed = false;
            foreach (string parameter in trackingParameters)
            {
                if (query[parameter] != null)
                {
                    query.Remove(parameter);
                    changed = true;
                }
            }
            if (!changed) return uri.AbsoluteUri;
            UriBuilder builder = new UriBuilder(uri);
            builder.Query = query.ToString();
            return builder.Uri.AbsoluteUri;
        }

        private static HashSet<string> LoadRequiredLines(string path)
        {
            FileInfo file = new FileInfo(path);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Required ZSEC policy is missing or unsafe: " + path);
            }
            return new HashSet<string>(
                File.ReadAllLines(path)
                    .Select(line => line.Trim().ToLowerInvariant())
                    .Where(line => line.Length > 0 && !line.StartsWith("#", StringComparison.Ordinal)),
                StringComparer.Ordinal
            );
        }

        private static void RejectReparseDirectory(string path)
        {
            DirectoryInfo directory = new DirectoryInfo(path);
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("ZSEC refused a reparse-point profile boundary: " + path);
            }
        }

        private static string SanitizeFileName(string name)
        {
            if (String.IsNullOrWhiteSpace(name)) name = "download.bin";
            foreach (char invalid in Path.GetInvalidFileNameChars())
            {
                name = name.Replace(invalid, '_');
            }
            return Truncate(name, 180);
        }

        private static string Truncate(string value, int maximum)
        {
            if (String.IsNullOrEmpty(value) || value.Length <= maximum) return value;
            return value.Substring(0, maximum - 1) + "...";
        }

        private void ShowBlockedNotice(string message)
        {
            runtimeStatus.Text = message;
        }

        private void WriteRuntimeEvidence(string runtimeVersion)
        {
            string evidencePath = Path.Combine(productRoot, "runtime-state.txt");
            string temporary = evidencePath + ".tmp-" + Guid.NewGuid().ToString("N");
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            bool elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            string[] lines =
            {
                "schema=zsec.browser.runtime.v1",
                "product=ZSEC Browser",
                "version=" + Program.ProductVersion,
                "engine=Microsoft Edge WebView2 Chromium",
                "engine_version=" + runtimeVersion,
                "profile_root=" + profileRoot,
                "tracker_domain_count=" + trackerDomains.Count.ToString(),
                "tracking_parameter_count=" + trackingParameters.Count.ToString(),
                "high_risk_mode=" + highRiskMode.ToString().ToLowerInvariant(),
                "blocked_request_count=" + blockedRequestCount.ToString(),
                "tracking_cleanup_count=" + trackingCleanupCount.ToString(),
                "last_navigation_https=" + lastNavigationHttps.ToString().ToLowerInvariant(),
                "host_objects_allowed=false",
                "web_messages_enabled=false",
                "password_autosave_enabled=false",
                "general_autofill_enabled=false",
                "permissions_default=deny",
                "elevated=" + elevated.ToString().ToLowerInvariant(),
                "process_id=" + Process.GetCurrentProcess().Id.ToString(),
                "checked_at=" + DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            };
            try
            {
                File.WriteAllLines(temporary, lines, new UTF8Encoding(false));
                if (File.Exists(evidencePath)) File.Replace(temporary, evidencePath, null);
                else File.Move(temporary, evidencePath);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }

        private void DisposeBrowserViews(object sender, FormClosedEventArgs args)
        {
            foreach (WebView2 view in browserViews.ToArray()) view.Dispose();
            browserViews.Clear();
        }
    }
}
