using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

[assembly: AssemblyTitle("ZSEC Browser")]
[assembly: AssemblyDescription("Hardened Windows browser shell powered by Microsoft Edge WebView2")]
[assembly: AssemblyCompany("TalkToAI")]
[assembly: AssemblyProduct("ZSEC Browser")]
[assembly: AssemblyCopyright("Copyright 2026 TalkToAI")]
[assembly: AssemblyVersion("0.3.21.0")]
[assembly: AssemblyFileVersion("0.3.21.0")]
[assembly: AssemblyInformationalVersion("0.3.21-community")]

namespace TalkToAI.ZsecBrowserPreview
{
    internal static class Program
    {
        internal const string ProductName = "ZSEC Browser";
        internal const string ProductVersion = "0.3.21";
        internal const string DefaultStartPage = "https://talktoai.org/zero-browser/";
        internal const string NewTabUri = "https://newtab.zsec.local/index.html";

        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            bool explicitDestination = args.Any(value =>
                !String.IsNullOrWhiteSpace(value) &&
                !value.StartsWith("--", StringComparison.Ordinal)
            );
            IList<string> destinations = ResolveDestinations(args, "brave");
            string destination = destinations[0];
            bool automationEnabled = args.Any(value => String.Equals(
                value, "--enable-local-automation", StringComparison.OrdinalIgnoreCase));
            try
            {
                bool runtimeNewTabTest = args.Any(value =>
                    String.Equals(
                        value,
                        "--zsec-runtime-test=new-tab",
                        StringComparison.OrdinalIgnoreCase
                    )
                );
                BrowserWindow window = new BrowserWindow(
                    destination,
                    explicitDestination,
                    runtimeNewTabTest,
                    destinations.Skip(1)
                );
                BrowserLocalAutomationServer automation = null;
                if (automationEnabled)
                {
                    string token = BrowserAutomationToken.CreateSessionToken();
                    automation = new BrowserLocalAutomationServer(
                        "zsec-browser-automation-" + Process.GetCurrentProcess().Id,
                        token,
                        window.HandleAutomationRequest
                    );
                    automation.Start();
                    Console.Error.WriteLine("ZSEC_AUTOMATION_PIPE=zsec-browser-automation-" + Process.GetCurrentProcess().Id);
                    Console.Error.WriteLine("ZSEC_AUTOMATION_TOKEN=" + token);
                }
                try { Application.Run(window); }
                finally { if (automation != null) automation.Dispose(); }
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "ZSEC Browser could not start.\r\n\r\n" + exception.Message,
                    ProductName,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        internal static string ResolveDestination(string[] args)
        {
            return ResolveDestination(args, "brave");
        }

        internal static string ResolveDestination(string[] args, string searchEngine)
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

            return BrowserSearchProviders.BuildSearchUrl(searchEngine, candidate);
        }

        internal static IList<string> ResolveDestinations(string[] args, string searchEngine)
        {
            List<string> result = new List<string>();
            foreach (string candidate in args.Where(value =>
                !String.IsNullOrWhiteSpace(value) && !value.StartsWith("--", StringComparison.Ordinal)).Take(32))
            {
                result.Add(ResolveDestination(new[] { candidate }, searchEngine));
            }
            if (result.Count == 0) result.Add(DefaultStartPage);
            return result;
        }
    }

    internal static class ModernUi
    {
        internal static GraphicsPath RoundedRectangle(Rectangle bounds, int radius)
        {
            int diameter = Math.Max(2, radius * 2);
            GraphicsPath path = new GraphicsPath();
            path.AddArc(bounds.Left, bounds.Top, diameter, diameter, 180, 90);
            path.AddArc(bounds.Right - diameter, bounds.Top, diameter, diameter, 270, 90);
            path.AddArc(bounds.Right - diameter, bounds.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(bounds.Left, bounds.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    internal sealed class RoundedSurface : Panel
    {
        internal Color SurfaceColor { get; set; }
        internal Color BorderColor { get; set; }
        internal Color FocusBorderColor { get; set; }
        internal bool ShowFocusCue { get; set; }
        internal int CornerRadius { get; set; }

        internal RoundedSurface()
        {
            DoubleBuffered = true;
            SurfaceColor = Color.FromArgb(17, 35, 44);
            BorderColor = Color.FromArgb(44, 73, 84);
            FocusBorderColor = Color.FromArgb(57, 220, 190);
            CornerRadius = 14;
            BackColor = Color.Transparent;
            Padding = new Padding(14, 7, 14, 7);
        }

        protected override void OnPaintBackground(PaintEventArgs args)
        {
            args.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle bounds = new Rectangle(1, 1, Math.Max(1, Width - 3), Math.Max(1, Height - 3));
            using (GraphicsPath path = ModernUi.RoundedRectangle(bounds, CornerRadius))
            using (SolidBrush brush = new SolidBrush(SurfaceColor))
            using (Pen pen = new Pen(ShowFocusCue ? FocusBorderColor : BorderColor, ShowFocusCue ? 1.5F : 1F))
            {
                args.Graphics.FillPath(brush, path);
                args.Graphics.DrawPath(pen, path);
            }
        }
    }

    // WinForms only owner-draws the individual tab headers. The native control still
    // paints the unused part of the tab well with a system colour, which produces a
    // bright strip in dark mode. Repaint the complete header after native painting so
    // the result is deterministic on Windows versions that ignore DarkMode_Explorer.
    internal sealed class DarkTabControl : TabControl
    {
        private const int WmPaint = 0x000F;
        private const int WmEraseBackground = 0x0014;
        internal Color StripBackColor { get; set; }
        internal Color StripBorderColor { get; set; }
        internal Color ContentBackColor { get; set; }
        internal Color ContentBorderColor { get; set; }

        internal DarkTabControl()
        {
            StripBackColor = Color.FromArgb(10, 23, 30);
            StripBorderColor = Color.FromArgb(42, 68, 78);
            ContentBackColor = StripBackColor;
            ContentBorderColor = StripBorderColor;
            SetStyle(ControlStyles.OptimizedDoubleBuffer, true);
            ResizeRedraw = true;
        }

        private int TabStripHeight
        {
            get
            {
                int bottom = 0;
                for (int index = 0; index < TabPages.Count; index++)
                {
                    bottom = Math.Max(bottom, GetTabRect(index).Bottom);
                }
                if (bottom > 0) return Math.Min(ClientSize.Height, bottom + 2);
                return Math.Min(ClientSize.Height, Math.Max(ItemSize.Height + 4, DisplayRectangle.Top));
            }
        }

        private void PaintTabStrip(Graphics graphics, bool paintTabs)
        {
            int height = TabStripHeight;
            if (height <= 0 || ClientSize.Width <= 0) return;
            using (SolidBrush background = new SolidBrush(StripBackColor))
            using (Pen border = new Pen(StripBorderColor))
            {
                graphics.FillRectangle(background, 0, 0, ClientSize.Width, height);
                graphics.DrawLine(border, 0, height - 1, ClientSize.Width, height - 1);
            }
            if (!paintTabs) return;
            for (int index = 0; index < TabPages.Count; index++)
            {
                Rectangle bounds = GetTabRect(index);
                OnDrawItem(new DrawItemEventArgs(
                    graphics,
                    Font,
                    bounds,
                    index,
                    index == SelectedIndex ? DrawItemState.Selected : DrawItemState.Default,
                    ForeColor,
                    StripBackColor
                ));
            }
        }

        private void PaintContentFrame(Graphics graphics)
        {
            Rectangle content = DisplayRectangle;
            if (content.Width <= 0 || content.Height <= 0) return;

            // Cover the native TabControl frame without painting over the hosted
            // WebView. This prevents a system black edge leaking into a themed
            // window while retaining a visible surface boundary.
            using (SolidBrush background = new SolidBrush(ContentBackColor))
            using (Pen border = new Pen(ContentBorderColor, 1F))
            {
                int stripHeight = TabStripHeight;
                if (content.Left > 0)
                    graphics.FillRectangle(background, 0, stripHeight, content.Left, ClientSize.Height - stripHeight);
                if (content.Right < ClientSize.Width)
                    graphics.FillRectangle(background, content.Right, stripHeight, ClientSize.Width - content.Right, ClientSize.Height - stripHeight);
                if (content.Bottom < ClientSize.Height)
                    graphics.FillRectangle(background, 0, content.Bottom, ClientSize.Width, ClientSize.Height - content.Bottom);
                graphics.DrawRectangle(border, content.Left, content.Top, Math.Max(0, content.Width - 1), Math.Max(0, content.Height - 1));
            }
        }

        protected override void WndProc(ref Message message)
        {
            if (message.Msg == WmEraseBackground && message.WParam != IntPtr.Zero)
            {
                using (Graphics graphics = Graphics.FromHdc(message.WParam))
                {
                    PaintTabStrip(graphics, false);
                }
                message.Result = new IntPtr(1);
                return;
            }

            base.WndProc(ref message);
            if (message.Msg != WmPaint || !IsHandleCreated) return;
            using (Graphics graphics = Graphics.FromHwnd(Handle))
            {
                PaintTabStrip(graphics, true);
                PaintContentFrame(graphics);
            }
        }
    }

    internal sealed class ModernToolStripRenderer : ToolStripProfessionalRenderer
    {
        private readonly Color hoverColor;
        private readonly Color pressedColor;

        internal ModernToolStripRenderer(Color hover, Color pressed)
            : base(new ProfessionalColorTable())
        {
            hoverColor = hover;
            pressedColor = pressed;
            RoundedEdges = false;
        }

        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs args)
        {
        }

        protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs args)
        {
            ToolStripButton button = args.Item as ToolStripButton;
            if (button == null || (!button.Selected && !button.Pressed && !button.Checked))
            {
                return;
            }

            Rectangle bounds = new Rectangle(2, 3, Math.Max(1, button.Width - 5), Math.Max(1, button.Height - 7));
            using (GraphicsPath path = ModernUi.RoundedRectangle(bounds, 8))
            using (SolidBrush brush = new SolidBrush(button.Pressed || button.Checked ? pressedColor : hoverColor))
            {
                args.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                args.Graphics.FillPath(brush, path);
            }
        }
    }

    internal sealed class RoundedActionButton : Button
    {
        private bool hovered;
        private bool pressed;

        internal Color SurfaceColor { get; set; }
        internal Color HoverColor { get; set; }
        internal Color PressedColor { get; set; }
        internal Color BorderColor { get; set; }
        internal int CornerRadius { get; set; }

        internal RoundedActionButton()
        {
            SetStyle(
                ControlStyles.UserPaint |
                ControlStyles.AllPaintingInWmPaint |
                ControlStyles.OptimizedDoubleBuffer |
                ControlStyles.ResizeRedraw,
                true
            );
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            SurfaceColor = Color.FromArgb(15, 34, 43);
            HoverColor = Color.FromArgb(24, 52, 63);
            PressedColor = Color.FromArgb(30, 74, 83);
            BorderColor = Color.FromArgb(42, 75, 88);
            CornerRadius = 10;
            Cursor = Cursors.Hand;
            TabStop = true;
        }

        protected override void OnMouseEnter(EventArgs args)
        {
            hovered = true;
            Invalidate();
            base.OnMouseEnter(args);
        }

        protected override void OnMouseLeave(EventArgs args)
        {
            hovered = false;
            pressed = false;
            Invalidate();
            base.OnMouseLeave(args);
        }

        protected override void OnMouseDown(MouseEventArgs args)
        {
            if (args.Button == MouseButtons.Left) pressed = true;
            Invalidate();
            base.OnMouseDown(args);
        }

        protected override void OnMouseUp(MouseEventArgs args)
        {
            pressed = false;
            Invalidate();
            base.OnMouseUp(args);
        }

        protected override void OnPaint(PaintEventArgs args)
        {
            args.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            Rectangle bounds = new Rectangle(1, 1, Math.Max(1, Width - 3), Math.Max(1, Height - 3));
            Color fill = pressed ? PressedColor : hovered ? HoverColor : SurfaceColor;
            using (GraphicsPath path = ModernUi.RoundedRectangle(bounds, CornerRadius))
            using (SolidBrush brush = new SolidBrush(fill))
            using (Pen border = new Pen(Focused ? Color.FromArgb(0, 229, 170) : BorderColor, Focused ? 1.5F : 1F))
            {
                args.Graphics.FillPath(brush, path);
                args.Graphics.DrawPath(border, path);
            }
            TextRenderer.DrawText(
                args.Graphics,
                Text,
                Font,
                ClientRectangle,
                ForeColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix
            );
        }
    }

    internal sealed class ProtectionPulse : Control
    {
        private readonly System.Windows.Forms.Timer timer;
        private int phase;
        private bool active;

        internal ProtectionPulse()
        {
            SetStyle(ControlStyles.SupportsTransparentBackColor, true);
            DoubleBuffered = true;
            Size = new Size(34, 34);
            BackColor = Color.Transparent;
            AccessibleName = "Protected navigation activity";
            timer = new System.Windows.Forms.Timer();
            timer.Interval = 45;
            timer.Tick += delegate
            {
                phase = (phase + 12) % 360;
                Invalidate();
            };
        }

        internal bool Active
        {
            get { return active; }
            set
            {
                active = value;
                if (active && SystemInformation.IsMenuAnimationEnabled)
                {
                    timer.Start();
                }
                else
                {
                    timer.Stop();
                    phase = 0;
                }
                Invalidate();
            }
        }

        protected override void OnPaint(PaintEventArgs args)
        {
            base.OnPaint(args);
            args.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            float wave = active
                ? (float)((Math.Sin(phase * Math.PI / 180D) + 1D) / 2D)
                : 0F;
            float haloRadius = 8F + (wave * 4F);
            PointF centre = new PointF(Width / 2F, Height / 2F);
            Color activeColour = Color.FromArgb(0, 229, 170);
            using (SolidBrush halo = new SolidBrush(Color.FromArgb((int)(28 + wave * 55), activeColour)))
            using (SolidBrush core = new SolidBrush(active ? activeColour : Color.FromArgb(65, 96, 107)))
            {
                args.Graphics.FillEllipse(
                    halo,
                    centre.X - haloRadius,
                    centre.Y - haloRadius,
                    haloRadius * 2F,
                    haloRadius * 2F
                );
                args.Graphics.FillEllipse(core, centre.X - 4F, centre.Y - 4F, 8F, 8F);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) timer.Dispose();
            base.Dispose(disposing);
        }
    }

    internal sealed class BrowserWindow : Form
    {
        private readonly BrowserThemePalette theme;
        private readonly Color Background;
        private readonly Color PanelBackground;
        private readonly Color ElevatedSurface;
        private readonly Color HoverSurface;
        private readonly Color Foreground;
        private readonly Color Accent;
        private readonly Color AccentBlue;
        private readonly Color Muted;
        private const int DwmUseImmersiveDarkMode = 20;
        private const int DwmWindowCornerPreference = 33;
        private const int DwmRound = 2;
        private const int MaximumTabs = 32;
        private const string ExpectedShieldsExtensionId = "ddjbjhnlhapggenanpmcidieimaomiif";
        private const string ShieldsSettingsBaseUri = "chrome-extension://ddjbjhnlhapggenanpmcidieimaomiif/popup/index.html";
        private static readonly IDictionary<string, string> ExpectedMicrosoftSystemExtensions =
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { "dgiklkfkllikcanfonkcabmbdfmgleag", "Microsoft Clipboard Extension" },
                { "mhjfbmdgcfjbbpaeojofohoefgiehjai", "Microsoft Edge PDF Viewer" }
            };
        private static readonly string[] ActiveHighRiskContexts =
        {
            "Script", "Document", "Stylesheet", "XmlHttpRequest", "Fetch", "WebSocket"
        };

        private readonly string initialDestination;
        private readonly IList<string> additionalDestinations;
        private readonly string applicationRoot;
        private readonly string productRoot;
        private readonly string profileRoot;
        private readonly string policyRoot;
        private readonly string extensionRoot;
        private readonly string newTabRoot;
        private readonly string youtubeProtectionPath;
        private readonly string extensionManifestSha256;
        private readonly string youtubeProtectionSha256;
        private readonly string youtubeProtectionSource;
        private readonly HashSet<string> trackerDomains;
        private readonly HashSet<string> trackingParameters;
        private readonly List<WebView2> browserViews;
        private readonly Dictionary<WebView2, string> youtubeScriptRegistrations;
        private readonly HashSet<WebView2> typedNavigationPending;
        private readonly DarkTabControl tabs;
        private readonly Panel tabHost;
        private readonly RoundedActionButton newTabButton;
        private readonly ToolStrip navigation;
        private readonly RoundedSurface addressSurface;
        private readonly TextBox address;
        private readonly ToolStripControlHost addressHost;
        private readonly Label shieldStatus;
        private readonly Label runtimeStatus;
        private readonly ProtectionPulse protectionPulse;
        private readonly ToolStripButton highRiskButton;
        private readonly ToolStripButton shieldsButton;
        private readonly ToolStripButton bookmarkButton;
        private readonly ToolStripButton menuButton;
        private readonly ToolStripLabel blockedLabel;
        private readonly ToolStripProgressBar navigationProgress;
        private readonly FlowLayoutPanel bookmarksBar;
        private readonly BrowserDataStore productStore;
        private readonly BrowserProductData productData;
        private readonly IVaultService vaultService;
        private readonly BrowserLoginAssistant loginAssistant;
        private readonly Dictionary<WebView2, string> loginRequestIds;
        private readonly BrowserCredentialRequestTracker loginRequestTracker;
        private readonly ContextMenuStrip mainMenu;
        private readonly NotifyIcon trayIcon;
        private CoreWebView2Environment environment;
        private int blockedRequestCount;
        private int nativeTrackerBlockCount;
        private int youtubeRequestBlockCount;
        private int youtubeScriptInterventionCount;
        private int trackingCleanupCount;
        private bool highRiskMode;
        private bool lastNavigationHttps;
        private bool shieldsExtensionEnabled;
        private bool dnrRuntimeVerified;
        private bool nativePolicySelfTestPassed;
        private bool nativeSubresourceRuntimeProbePassed;
        private bool youtubeScriptLoaded;
        private bool youtubeStatusRefreshActive;
        private bool runtimeUpdateAvailable;
        private bool isClosing;
        private bool exitRequested;
        private bool trayNoticeShown;
        private string productDataWarning;
        private string installedShieldsExtensionId = "unavailable";
        private string effectiveTrackingPrevention = "unavailable";
        private Task extensionInstallTask;
        private int popupRequestCount;
        private int popupAllowedCount;
        private int popupBlockedCount;
        private int tabCreationFailureCount;
        private string lastTabAction = "startup";
        private string lastNewTabCommandSource = "none";
        private readonly bool runtimeNewTabTest;
        private readonly TaskCompletionSource<bool> environmentReady;
        private readonly SemaphoreSlim tabMutationGate;
        private readonly System.Windows.Forms.Timer youtubeStatusTimer;
        private readonly Dictionary<Control, bool> fullScreenControlVisibility;
        private bool isFullScreen;
        private FormBorderStyle windowedBorderStyle;
        private FormWindowState windowedState;
        private Size windowedTabItemSize;

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(
            IntPtr window,
            int attribute,
            ref int value,
            int valueSize
        );

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr handle, string subAppName, string subIdList);

        internal BrowserWindow(
            string destination,
            bool explicitDestination,
            bool testNewTab = false,
            IEnumerable<string> extraDestinations = null
        )
        {
            runtimeNewTabTest = testNewTab;
            additionalDestinations = (extraDestinations ?? Enumerable.Empty<string>()).Take(MaximumTabs - 1).ToList();
            applicationRoot = AppDomain.CurrentDomain.BaseDirectory;
            productRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "TalkToAI",
                "ZSEC Browser"
            );
            vaultService = new BrowserVaultService(productRoot);
            productStore = new BrowserDataStore(productRoot);
            try
            {
                productData = productStore.Load();
            }
            catch (Exception exception)
            {
                productData = BrowserProductData.CreateDefault();
                productDataWarning = "Local bookmarks, history and settings could not be loaded: " +
                    exception.Message;
            }
            theme = BrowserThemePalette.Resolve(productData.Settings);
            Background = theme.Background;
            PanelBackground = theme.Panel;
            ElevatedSurface = theme.Surface;
            HoverSurface = theme.Hover;
            Foreground = theme.Foreground;
            Accent = theme.Accent;
            AccentBlue = theme.AccentSecondary;
            Muted = theme.Muted;
            BrowserDialogTheme.Configure(theme);
            loginRequestIds = new Dictionary<WebView2, string>();
            loginRequestTracker = new BrowserCredentialRequestTracker();
            loginAssistant = new BrowserLoginAssistant(
                vaultService,
                delegate { return productData.Settings; },
                delegate { productStore.Save(productData); }
            );
            initialDestination = explicitDestination
                ? destination
                : GetStartupDestination(productData.Settings);
            profileRoot = Path.Combine(productRoot, "User Data");
            policyRoot = Path.Combine(applicationRoot, "policy");
            extensionRoot = Path.Combine(applicationRoot, "extension");
            newTabRoot = Path.Combine(applicationRoot, "new-tab");
            youtubeProtectionPath = Path.Combine(applicationRoot, "youtube-player-protection.js");
            extensionManifestSha256 = ComputeSha256RegularFile(
                Path.Combine(extensionRoot, "manifest.json")
            );
            youtubeProtectionSha256 = ComputeSha256RegularFile(youtubeProtectionPath);
            youtubeProtectionSource = ReadBoundedRegularText(youtubeProtectionPath, 128 * 1024);
            trackerDomains = LoadRequiredLines(Path.Combine(policyRoot, "tracker-domains.txt"));
            trackingParameters = LoadRequiredLines(Path.Combine(policyRoot, "tracking-parameters.txt"));
            browserViews = new List<WebView2>();
            youtubeScriptRegistrations = new Dictionary<WebView2, string>();
            typedNavigationPending = new HashSet<WebView2>();
            fullScreenControlVisibility = new Dictionary<Control, bool>();
            environmentReady = new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously
            );
            tabMutationGate = new SemaphoreSlim(1, 1);
            highRiskMode = productData.Settings.NativeStrictMode;
            nativePolicySelfTestPassed = RunNativePolicySelfTest();
            youtubeStatusTimer = new System.Windows.Forms.Timer();
            youtubeStatusTimer.Interval = 3000;
            youtubeStatusTimer.Tick += async delegate
            {
                WebView2 current = ActiveView;
                if (current != null) await RefreshYoutubeProtectionStatusAsync(current);
            };
            youtubeStatusTimer.Start();

            Text = "ZSEC Browser";
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            StartPosition = FormStartPosition.CenterScreen;
            WindowState = FormWindowState.Maximized;
            MinimumSize = new Size(960, 640);
            BackColor = Background;
            ForeColor = Foreground;
            KeyPreview = true;
            DoubleBuffered = true;
            AutoScaleMode = AutoScaleMode.Font;
            Font = new Font("Segoe UI", 9F);

            Panel brandBar = new Panel();
            brandBar.Dock = DockStyle.Top;
            brandBar.Height = 58;
            brandBar.BackColor = Background;

            Label brand = new Label();
            brand.Text = "ZSEC";
            brand.Font = new Font("Segoe UI Semibold", 17F, FontStyle.Bold);
            brand.ForeColor = Accent;
            brand.AutoSize = true;
            brand.Location = new Point(20, 12);
            brandBar.Controls.Add(brand);

            Label product = new Label();
            product.Text = "BROWSER";
            product.Font = new Font("Segoe UI", 11F, FontStyle.Regular);
            product.ForeColor = AccentBlue;
            product.AutoSize = true;
            product.Location = new Point(88, 20);
            brandBar.Controls.Add(product);

            Label channel = new Label();
            channel.Text = "COMMUNITY 0.3.21";
            channel.Font = new Font("Segoe UI", 8F, FontStyle.Bold);
            channel.ForeColor = Muted;
            channel.AutoSize = true;
            channel.Location = new Point(184, 22);
            brandBar.Controls.Add(channel);

            protectionPulse = new ProtectionPulse();
            protectionPulse.Location = new Point(324, 12);
            brandBar.Controls.Add(protectionPulse);

            shieldStatus = new Label();
            shieldStatus.Text = "  SHIELDS: VERIFYING  ";
            shieldStatus.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold);
            shieldStatus.ForeColor = Background;
            shieldStatus.BackColor = Color.FromArgb(245, 185, 66);
            shieldStatus.AutoSize = true;
            shieldStatus.Padding = new Padding(8, 6, 8, 6);
            shieldStatus.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            shieldStatus.Location = new Point(ClientSize.Width - 164, 11);
            brandBar.Controls.Add(shieldStatus);
            brandBar.Resize += delegate
            {
                shieldStatus.Location = new Point(brandBar.ClientSize.Width - shieldStatus.Width - 20, 11);
            };

            navigation = new ToolStrip();
            navigation.Dock = DockStyle.Top;
            navigation.GripStyle = ToolStripGripStyle.Hidden;
            navigation.RenderMode = ToolStripRenderMode.Professional;
            navigation.Renderer = new ModernToolStripRenderer(HoverSurface, Color.FromArgb(30, 74, 83));
            navigation.BackColor = PanelBackground;
            navigation.ForeColor = Foreground;
            navigation.Padding = new Padding(12, 8, 12, 8);
            navigation.ImageScalingSize = new Size(20, 20);
            navigation.AutoSize = false;
            navigation.Height = 54;
            navigation.AccessibleName = "Browser navigation toolbar";

            ToolStripButton backButton = CreateButton("‹", "Back (Alt+Left)", delegate { if (ActiveView != null && ActiveView.CanGoBack) ActiveView.GoBack(); });
            ToolStripButton forwardButton = CreateButton("›", "Forward (Alt+Right)", delegate { if (ActiveView != null && ActiveView.CanGoForward) ActiveView.GoForward(); });
            ToolStripButton reloadButton = CreateButton("↻", "Reload (Ctrl+R)", delegate { if (ActiveView != null) ActiveView.Reload(); });
            ToolStripButton homeButton = CreateButton("⌂", "ZSEC home", delegate { Navigate(Program.DefaultStartPage); });

            addressSurface = new RoundedSurface();
            addressSurface.Size = new Size(660, 36);
            addressSurface.SurfaceColor = ElevatedSurface;
            addressSurface.BorderColor = theme.Border;
            addressSurface.FocusBorderColor = Accent;
            addressSurface.CornerRadius = 16;
            address = new TextBox();
            address.BorderStyle = BorderStyle.None;
            address.BackColor = ElevatedSurface;
            address.ForeColor = Color.FromArgb(228, 240, 244);
            address.Font = new Font("Segoe UI", 10.5F);
            address.Location = new Point(14, 9);
            address.Width = addressSurface.Width - 28;
            address.Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top;
            address.AccessibleName = "Address and search";
            address.AutoCompleteMode = AutoCompleteMode.SuggestAppend;
            address.AutoCompleteSource = AutoCompleteSource.CustomSource;
            address.KeyDown += AddressKeyDown;
            address.Enter += delegate
            {
                addressSurface.ShowFocusCue = true;
                addressSurface.Invalidate();
            };
            address.Leave += delegate
            {
                addressSurface.ShowFocusCue = false;
                addressSurface.Invalidate();
            };
            addressSurface.Controls.Add(address);
            RefreshAddressSuggestions();
            addressHost = new ToolStripControlHost(addressSurface);
            addressHost.AutoSize = false;
            addressHost.Width = 660;
            addressHost.Height = 38;
            addressHost.Margin = new Padding(7, 0, 7, 0);

            highRiskButton = CreateButton(
                BrowserToolbarLayout.NativeGuardLabel(highRiskMode, navigation.ClientSize.Width),
                "Toggle stricter native navigation policy",
                ToggleHighRiskMode
            );
            highRiskButton.CheckOnClick = false;
            highRiskButton.Checked = highRiskMode;
            shieldsButton = CreateButton("Shields", "Open ZSEC Browser Shields controls", async delegate { await OpenShieldsSettingsAsync(); });
            bookmarkButton = CreateButton("☆", "Bookmark this page (Ctrl+D)", AddActiveBookmark);
            menuButton = CreateButton("☰", "ZSEC Browser main menu (Alt+F)", delegate { ShowMainMenu(); });
            mainMenu = BuildMainMenu();

            navigation.Items.AddRange(new ToolStripItem[]
            {
                backButton,
                forwardButton,
                reloadButton,
                homeButton,
                addressHost,
                new ToolStripSeparator(),
                bookmarkButton,
                highRiskButton,
                shieldsButton,
                menuButton
            });
            navigation.Resize += delegate
            {
                LayoutNavigationToolbar();
            };

            tabs = new DarkTabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.Font = new Font("Segoe UI Semibold", 9F);
            tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            tabs.ItemSize = new Size(210, 36);
            tabs.SizeMode = TabSizeMode.Fixed;
            tabs.Padding = new Point(18, 5);
            tabs.HotTrack = true;
            tabs.BackColor = Background;
            tabs.ForeColor = Foreground;
            tabs.StripBackColor = Background;
            tabs.StripBorderColor = theme.Border;
            tabs.ContentBackColor = Background;
            tabs.ContentBorderColor = theme.Border;
            tabs.AccessibleName = "Open browser tabs";
            tabs.HandleCreated += delegate
            {
                SetWindowTheme(tabs.Handle, "DarkMode_Explorer", null);
            };
            tabs.DrawItem += DrawBrowserTab;
            tabs.MouseDown += BrowserTabMouseDown;
            tabs.SelectedIndexChanged += delegate
            {
                UpdateAddressFromActiveView();
                PositionNewTabButton();
                WebView2 selected = ActiveView;
                SetFullScreen(
                    selected != null &&
                    selected.CoreWebView2 != null &&
                    selected.CoreWebView2.ContainsFullScreenElement
                );
            };

            tabHost = new Panel();
            tabHost.Dock = DockStyle.Fill;
            tabHost.BackColor = Background;
            tabHost.Controls.Add(tabs);
            newTabButton = new RoundedActionButton();
            newTabButton.Text = "+";
            newTabButton.Font = new Font("Segoe UI", 15F, FontStyle.Regular);
            newTabButton.ForeColor = Foreground;
            newTabButton.Size = new Size(38, 30);
            newTabButton.AccessibleName = "New tab";
            newTabButton.AccessibleDescription = "Open a protected local new tab (Ctrl+T)";
            newTabButton.Click += async delegate { await CreateNewTabCommandAsync("tab_strip"); };
            tabHost.Controls.Add(newTabButton);
            newTabButton.BringToFront();
            tabHost.Resize += delegate { PositionNewTabButton(); };

            bookmarksBar = new FlowLayoutPanel();
            bookmarksBar.Dock = DockStyle.Top;
            bookmarksBar.Height = 38;
            bookmarksBar.Padding = new Padding(12, 4, 12, 3);
            bookmarksBar.WrapContents = false;
            bookmarksBar.AutoScroll = true;
            bookmarksBar.FlowDirection = FlowDirection.LeftToRight;
            bookmarksBar.BackColor = PanelBackground;
            bookmarksBar.AccessibleName = "Bookmarks bar";
            bookmarksBar.Visible = productData.Settings.ShowBookmarksBar;
            RefreshBookmarksBar();

            StatusStrip status = new StatusStrip();
            status.BackColor = PanelBackground;
            status.ForeColor = Muted;
            status.RenderMode = ToolStripRenderMode.Professional;
            status.Renderer = new ModernToolStripRenderer(HoverSurface, ElevatedSurface);
            status.SizingGrip = false;
            runtimeStatus = new Label();
            runtimeStatus.Text = "Starting Microsoft Chromium runtime...";
            runtimeStatus.ForeColor = Muted;
            runtimeStatus.AutoSize = true;
            runtimeStatus.AccessibleName = "Browser runtime status";
            ToolStripControlHost runtimeHost = new ToolStripControlHost(runtimeStatus);
            blockedLabel = new ToolStripLabel("Native policy blocks: 0");
            blockedLabel.ForeColor = Accent;
            blockedLabel.AccessibleName = "Native policy block count";
            navigationProgress = new ToolStripProgressBar();
            navigationProgress.Style = ProgressBarStyle.Marquee;
            navigationProgress.MarqueeAnimationSpeed = 24;
            navigationProgress.Size = new Size(90, 8);
            navigationProgress.ToolTipText = "Navigation in progress";
            navigationProgress.Visible = false;
            ToolStripStatusLabel spacer = new ToolStripStatusLabel();
            spacer.Spring = true;
            status.Items.Add(runtimeHost);
            status.Items.Add(navigationProgress);
            status.Items.Add(spacer);
            status.Items.Add(blockedLabel);
            status.Items.Add(new ToolStripStatusLabel("Profile: separate app data"));

            trayIcon = new NotifyIcon();
            trayIcon.Icon = Icon;
            trayIcon.Text = "ZSEC Browser Community";
            trayIcon.ContextMenuStrip = BuildTrayMenu();
            trayIcon.Visible = productData.Settings.MinimizeToTray || productData.Settings.CloseToTray;
            trayIcon.DoubleClick += delegate { RestoreFromTray(); };

            Controls.Add(tabHost);
            Controls.Add(status);
            Controls.Add(bookmarksBar);
            Controls.Add(navigation);
            Controls.Add(brandBar);

            Load += InitializeBrowserAsync;
            Resize += BrowserWindowResize;
            FormClosing += BrowserWindowClosing;
            FormClosed += DisposeBrowserViews;
            KeyDown += BrowserKeyDown;
            WriteStartupStage("window_constructed");
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

        internal BrowserAutomationResponse HandleAutomationRequest(BrowserAutomationRequest request)
        {
            if (InvokeRequired)
            {
                return (BrowserAutomationResponse)Invoke(
                    new Func<BrowserAutomationRequest, BrowserAutomationResponse>(HandleAutomationRequest),
                    request
                );
            }

            BrowserAutomationResponse response = new BrowserAutomationResponse
            {
                Ok = true,
                Version = Program.ProductVersion,
                TabCount = tabs.TabPages.Count,
                ActiveTab = tabs.SelectedIndex,
                WindowVisible = Visible && WindowState != FormWindowState.Minimized,
                AutomationEnabled = true
            };
            if (request.Command == "ping" || request.Command == "get_state") return response;
            if (request.Command == "activate")
            {
                RestoreFromTray();
                Activate();
                return response;
            }

            string normalized;
            if (!BrowserLocalAutomationPolicy.TryNormalizeUrl(request.Url, out normalized))
                return new BrowserAutomationResponse { Ok = false, Error = "invalid_url", AutomationEnabled = true };

            if (request.Command == "open_url")
            {
                Navigate(normalized);
            }
            else if (request.Command == "open_tab")
            {
                if (tabs.TabPages.Count >= MaximumTabs)
                    return new BrowserAutomationResponse { Ok = false, Error = "tab_limit", AutomationEnabled = true };
                BeginInvoke(new Action(async delegate { await CreateTab(normalized, true); }));
            }
            return response;
        }

        protected override void OnHandleCreated(EventArgs args)
        {
            base.OnHandleCreated(args);
            WriteStartupStage("window_handle_created");
            try
            {
                int darkMode = 1;
                DwmSetWindowAttribute(Handle, DwmUseImmersiveDarkMode, ref darkMode, sizeof(int));
                int cornerPreference = DwmRound;
                DwmSetWindowAttribute(Handle, DwmWindowCornerPreference, ref cornerPreference, sizeof(int));
            }
            catch (DllNotFoundException)
            {
            }
            catch (EntryPointNotFoundException)
            {
            }
        }

        private ToolStripButton CreateButton(string text, string toolTip, EventHandler handler)
        {
            ToolStripButton button = new ToolStripButton(text);
            button.DisplayStyle = ToolStripItemDisplayStyle.Text;
            button.ForeColor = Foreground;
            button.Font = new Font("Segoe UI Symbol", text.Length <= 2 ? 14F : 9F, FontStyle.Bold);
            button.AutoSize = false;
            button.Size = new Size(text.Length > 2 ? ToolbarTextButtonWidth(button) : 42, 34);
            button.Margin = new Padding(2, 0, 2, 0);
            button.ToolTipText = toolTip;
            button.AccessibleName = toolTip;
            button.Click += handler;
            return button;
        }

        private static int ToolbarTextButtonWidth(ToolStripButton button)
        {
            Size measured = TextRenderer.MeasureText(
                button.Text,
                button.Font,
                Size.Empty,
                TextFormatFlags.NoPadding | TextFormatFlags.SingleLine
            );
            return Math.Max(72, measured.Width + 24);
        }

        private void LayoutNavigationToolbar()
        {
            if (navigation == null || addressHost == null || highRiskButton == null) return;

            highRiskButton.Text = BrowserToolbarLayout.NativeGuardLabel(
                highRiskMode,
                navigation.ClientSize.Width
            );
            highRiskButton.Width = ToolbarTextButtonWidth(highRiskButton);
            shieldsButton.Width = ToolbarTextButtonWidth(shieldsButton);

            int fixedWidth = navigation.Padding.Horizontal + addressHost.Margin.Horizontal;
            foreach (ToolStripItem item in navigation.Items)
            {
                if (Object.ReferenceEquals(item, addressHost)) continue;
                fixedWidth += item.Width + item.Margin.Horizontal;
            }
            addressHost.Width = BrowserToolbarLayout.AddressWidth(
                navigation.ClientSize.Width,
                fixedWidth
            );
            addressSurface.Width = addressHost.Width;
        }

        private ContextMenuStrip BuildMainMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            ApplyMenuTheme(menu);
            menu.ShowImageMargin = false;
            menu.Font = new Font("Segoe UI", 9.5F);
            menu.AccessibleName = "ZSEC Browser main menu";
            ToolStripMenuItem status = new ToolStripMenuItem("Protection status: starting");
            status.Enabled = false;
            status.Tag = "protection_status";
            menu.Items.Add(status);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(MenuItem("New tab", "Ctrl+T", async delegate { await CreateNewTabCommandAsync("main_menu"); }));
            menu.Items.Add(MenuItem("Bookmark this page", "Ctrl+D", AddActiveBookmark));

            ToolStripMenuItem bookmarks = new ToolStripMenuItem("Bookmarks");
            bookmarks.DropDownItems.Add(MenuItem("Show bookmarks bar", "Ctrl+Shift+B", ToggleBookmarksBar));
            bookmarks.DropDownItems.Add(MenuItem("Bookmark manager", "Ctrl+Shift+O", delegate { ShowBookmarksManager(); }));
            bookmarks.DropDownItems.Add(new ToolStripSeparator());
            bookmarks.DropDownItems.Add(MenuItem("Import bookmarks", "", delegate { ImportBookmarks(); }));
            bookmarks.DropDownItems.Add(MenuItem("Export bookmarks", "", delegate { ExportBookmarks(); }));
            menu.Items.Add(bookmarks);

            menu.Items.Add(MenuItem("History", "Ctrl+H", delegate { ShowHistory(); }));
            menu.Items.Add(MenuItem("Clear browsing history", "Ctrl+Shift+Del", delegate { ClearBrowsingHistory(); }));
            menu.Items.Add(MenuItem("Passwords", "Ctrl+Shift+P", delegate { ShowPasswords(); }));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(MenuItem("ZSEC Shields", "", async delegate { await OpenShieldsSettingsAsync(); }));
            menu.Items.Add(MenuItem("Settings", "Ctrl+,", async delegate { await ShowSettingsAsync(); }));
            menu.Items.Add(MenuItem("Set as default browser", "", OpenDefaultApps));
            menu.Items.Add(MenuItem("About ZSEC Browser", "", ShowAbout));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(MenuItem("Minimize to tray", "", delegate { HideToTray(); }));
            menu.Items.Add(MenuItem("Exit ZSEC Browser", "", delegate { ExitBrowser(); }));
            return menu;
        }

        private ContextMenuStrip BuildTrayMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            ApplyMenuTheme(menu);
            menu.ShowImageMargin = false;
            menu.Font = new Font("Segoe UI", 9.5F);
            menu.AccessibleName = "ZSEC Browser notification area menu";
            menu.Items.Add(MenuItem("Show ZSEC Browser", "", delegate { RestoreFromTray(); }));
            menu.Items.Add(MenuItem("New tab", "Ctrl+T", async delegate
            {
                RestoreFromTray();
                await CreateNewTabCommandAsync("tray_menu");
            }));
            ToolStripMenuItem protection = new ToolStripMenuItem("Protection status is shown in the browser window");
            protection.Enabled = false;
            menu.Items.Add(protection);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(MenuItem("Settings", "Ctrl+,", async delegate
            {
                RestoreFromTray();
                await ShowSettingsAsync();
            }));
            menu.Items.Add(MenuItem("Exit ZSEC Browser", "", delegate { ExitBrowser(); }));
            return menu;
        }

        private void ApplyMenuTheme(ContextMenuStrip menu)
        {
            menu.BackColor = PanelBackground;
            menu.ForeColor = Foreground;
            menu.Renderer = new ModernToolStripRenderer(HoverSurface, ElevatedSurface);
        }

        private static ToolStripMenuItem MenuItem(
            string text,
            string shortcut,
            EventHandler handler
        )
        {
            ToolStripMenuItem item = new ToolStripMenuItem(text);
            item.ShowShortcutKeys = true;
            item.ShortcutKeyDisplayString = shortcut;
            item.AccessibleName = String.IsNullOrWhiteSpace(shortcut)
                ? text
                : text + " (" + shortcut + ")";
            item.Click += handler;
            return item;
        }

        private void ShowMainMenu()
        {
            foreach (ToolStripItem item in mainMenu.Items)
            {
                if (String.Equals(item.Tag as string, "protection_status", StringComparison.Ordinal))
                {
                    item.Text = shieldsExtensionEnabled
                        ? dnrRuntimeVerified
                            ? "Protection status: Shields verified in this session"
                            : "Protection status: Shields loaded; DNR probe not passed"
                        : "Protection status: Shields unavailable";
                }
            }
            mainMenu.Show(menuButton.GetCurrentParent(), new Point(menuButton.Bounds.Left, menuButton.Bounds.Bottom));
        }

        private void OpenDefaultApps(object sender, EventArgs args)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:defaultapps",
                    UseShellExecute = true
                });
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "Windows Default Apps could not be opened. Open Settings > Apps > Default apps, select ZSEC Browser, and confirm the associations you want.\r\n\r\n" + exception.Message,
                    "Set ZSEC Browser as default",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
        }

        private void RefreshBookmarksBar()
        {
            if (bookmarksBar == null) return;
            bookmarksBar.SuspendLayout();
            try
            {
                bookmarksBar.Controls.Clear();
                foreach (BrowserBookmark bookmark in productData.Bookmarks.Take(12))
                {
                    Button button = BrowserDialogTheme.Button(
                        Truncate(bookmark.Title, 24),
                        "Open bookmark " + bookmark.Title
                    );
                    button.AutoSize = false;
                    button.Height = 28;
                    button.Width = Math.Min(180, Math.Max(86, TextRenderer.MeasureText(button.Text, Font).Width + 24));
                    button.Margin = new Padding(2, 0, 2, 0);
                    button.Tag = bookmark.Url;
                    button.Click += delegate(object sender, EventArgs args)
                    {
                        Button selected = sender as Button;
                        if (selected != null) Navigate(selected.Tag as string);
                    };
                    bookmarksBar.Controls.Add(button);
                }
                Button manage = BrowserDialogTheme.Button("Bookmarks", "Open bookmark manager");
                manage.AutoSize = false;
                manage.Size = new Size(104, 28);
                manage.Margin = new Padding(4, 0, 2, 0);
                manage.Click += delegate { ShowBookmarksManager(); };
                bookmarksBar.Controls.Add(manage);
            }
            finally
            {
                bookmarksBar.ResumeLayout();
            }
        }

        private void AddActiveBookmark(object sender, EventArgs args)
        {
            if (!CanPersistProductData(true)) return;
            WebView2 view = ActiveView;
            if (view == null || view.Source == null || !IsAllowedWebUri(view.Source.ToString(), true))
            {
                runtimeStatus.Text = "Only HTTP or HTTPS pages can be bookmarked.";
                return;
            }
            string title = view.CoreWebView2 == null ? view.Source.Host : view.CoreWebView2.DocumentTitle;
            bool added;
            try
            {
                added = productStore.AddBookmark(productData, title, view.Source.AbsoluteUri);
            }
            catch (Exception exception)
            {
                ShowProductDataWriteFailure(exception);
                return;
            }
            RefreshBookmarksBar();
            RefreshAddressSuggestions();
            UpdateBookmarkButton();
            runtimeStatus.Text = added ? "Bookmark saved locally." : "Bookmark title updated locally.";
        }

        private void UpdateBookmarkButton()
        {
            if (bookmarkButton == null) return;
            string current = ActiveView == null || ActiveView.Source == null
                ? String.Empty
                : ActiveView.Source.AbsoluteUri;
            bool saved = productData.Bookmarks.Any(item =>
                String.Equals(item.Url, current, StringComparison.OrdinalIgnoreCase)
            );
            bookmarkButton.Text = saved ? "★" : "☆";
            bookmarkButton.ToolTipText = saved ? "This page is bookmarked" : "Bookmark this page (Ctrl+D)";
            bookmarkButton.AccessibleName = bookmarkButton.ToolTipText;
        }

        private void ShowBookmarksManager()
        {
            if (!CanPersistProductData(true)) return;
            using (BookmarksDialog dialog = new BookmarksDialog(
                productStore,
                productData,
                delegate(string url) { Navigate(url); }
            ))
            {
                dialog.ShowDialog(this);
            }
            RefreshBookmarksBar();
            RefreshAddressSuggestions();
            UpdateBookmarkButton();
        }

        private void ImportBookmarks()
        {
            if (!CanPersistProductData(true)) return;
            OpenFileDialog picker = new OpenFileDialog();
            picker.Filter = "Bookmark HTML (*.html;*.htm)|*.html;*.htm|All files (*.*)|*.*";
            picker.CheckFileExists = true;
            if (picker.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                int added = productStore.ImportBookmarksHtml(productData, picker.FileName);
                RefreshBookmarksBar();
                RefreshAddressSuggestions();
                runtimeStatus.Text = added.ToString() + " bookmark(s) imported locally.";
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "Bookmarks were not imported.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }

        private void ExportBookmarks()
        {
            SaveFileDialog picker = new SaveFileDialog();
            picker.Filter = "Bookmark HTML (*.html)|*.html";
            picker.FileName = "zsec-browser-bookmarks.html";
            picker.OverwritePrompt = true;
            if (picker.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                productStore.ExportBookmarksHtml(productData, picker.FileName);
                runtimeStatus.Text = "Bookmarks exported to " + picker.FileName;
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "Bookmarks were not exported.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }

        private void ToggleBookmarksBar(object sender, EventArgs args)
        {
            if (!CanPersistProductData(true)) return;
            productData.Settings.ShowBookmarksBar = !productData.Settings.ShowBookmarksBar;
            bookmarksBar.Visible = productData.Settings.ShowBookmarksBar;
            try
            {
                productStore.Save(productData);
            }
            catch (Exception exception)
            {
                productData.Settings.ShowBookmarksBar = !productData.Settings.ShowBookmarksBar;
                bookmarksBar.Visible = productData.Settings.ShowBookmarksBar;
                ShowProductDataWriteFailure(exception);
            }
        }

        private void ShowHistory()
        {
            if (!CanPersistProductData(true)) return;
            using (HistoryDialog dialog = new HistoryDialog(
                productStore,
                productData,
                delegate(string url) { Navigate(url); }
            ))
            {
                dialog.ShowDialog(this);
            }
        }

        private void ClearBrowsingHistory()
        {
            if (!CanPersistProductData(true)) return;
            DialogResult answer = MessageBox.Show(
                "Clear all locally stored ZSEC Browser history? Bookmarks are preserved.",
                "Clear browsing history",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2
            );
            if (answer != DialogResult.Yes) return;
            try
            {
                productStore.ClearHistory(productData);
                RefreshAddressSuggestions();
                runtimeStatus.Text = "Local browsing history cleared.";
            }
            catch (Exception exception)
            {
                ShowProductDataWriteFailure(exception);
            }
        }

        private async Task ShowSettingsAsync()
        {
            BrowserRuntimeSnapshot snapshot = new BrowserRuntimeSnapshot
            {
                RuntimeVersion = environment == null
                    ? "not initialized"
                    : CoreWebView2Environment.GetAvailableBrowserVersionString(),
                ShieldsExtensionLoaded = shieldsExtensionEnabled,
                DnrProbePassed = dnrRuntimeVerified,
                TrackingPrevention = effectiveTrackingPrevention,
                RuntimeUpdateAvailable = runtimeUpdateAvailable
            };
            using (SettingsDialog dialog = new SettingsDialog(productData.Settings, snapshot))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                if (!CanPersistProductData(true))
                {
                    if (dialog.OpenShieldsRequested) await OpenShieldsSettingsAsync();
                    return;
                }
                BrowserSettings previous = productData.Settings;
                try
                {
                    productData.Settings = dialog.Result;
                    productStore.Save(productData);
                    ApplyProductSettings();
                    bool themeChanged =
                        !String.Equals(previous.Theme, productData.Settings.Theme, StringComparison.Ordinal) ||
                        !String.Equals(previous.AccentColor, productData.Settings.AccentColor, StringComparison.Ordinal);
                    if (themeChanged)
                    {
                        runtimeStatus.Text = "Theme saved · restart ZSEC Browser to recolour every open native surface.";
                    }
                    if (previous.BlockYoutubeAds != productData.Settings.BlockYoutubeAds)
                    {
                        await ApplyYoutubeProtectionSettingAsync();
                    }
                    if (dialog.ClearHistoryRequested)
                    {
                        productStore.ClearHistory(productData);
                        RefreshAddressSuggestions();
                    }
                }
                catch (Exception exception)
                {
                    productData.Settings = previous;
                    ApplyProductSettings();
                    ShowProductDataWriteFailure(exception);
                    return;
                }
                if (dialog.OpenPasswordsRequested)
                {
                    ShowPasswords();
                    return;
                }
                if (dialog.OpenShieldsRequested) await OpenShieldsSettingsAsync();
            }
        }

        private void ShowPasswords()
        {
            using (BrowserVaultDialog dialog = new BrowserVaultDialog(
                vaultService,
                new WindowsBrowserClipboard()
            ))
            {
                dialog.ShowDialog(this);
            }
        }

        private bool CanPersistProductData(bool notify)
        {
            if (String.IsNullOrWhiteSpace(productDataWarning)) return true;
            runtimeStatus.Text = Truncate(productDataWarning, 140);
            if (notify)
            {
                MessageBox.Show(
                    productDataWarning +
                        "\r\n\r\nZSEC preserved the existing data file and will not overwrite it during this session.",
                    "ZSEC Browser local data",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
            return false;
        }

        private void ShowProductDataWriteFailure(Exception exception)
        {
            MessageBox.Show(
                "The local browser-data change was not saved.\r\n\r\n" + exception.Message,
                "ZSEC Browser local data",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
            );
        }

        private void ApplyProductSettings()
        {
            highRiskMode = productData.Settings.NativeStrictMode;
            LayoutNavigationToolbar();
            highRiskButton.Checked = highRiskMode;
            highRiskButton.BackColor = highRiskMode ? Color.FromArgb(210, 74, 54) : PanelBackground;
            bookmarksBar.Visible = productData.Settings.ShowBookmarksBar;
            trayIcon.Visible = productData.Settings.MinimizeToTray || productData.Settings.CloseToTray;
            ApplyLoginAssistantSettings();
            RefreshBookmarksBar();
            if (environment != null)
            {
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            }
        }

        private async Task ApplyYoutubeProtectionSettingAsync()
        {
            foreach (WebView2 view in browserViews.ToArray())
            {
                if (view == null || view.CoreWebView2 == null) continue;
                string registration;
                if (productData.Settings.BlockYoutubeAds &&
                    !youtubeScriptRegistrations.ContainsKey(view))
                {
                    registration = await view.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(
                        youtubeProtectionSource
                    );
                    youtubeScriptRegistrations[view] = registration;
                }
                else if (!productData.Settings.BlockYoutubeAds &&
                    youtubeScriptRegistrations.TryGetValue(view, out registration))
                {
                    view.CoreWebView2.RemoveScriptToExecuteOnDocumentCreated(registration);
                    youtubeScriptRegistrations.Remove(view);
                }
                if (view.Source != null && BrowserRequestPolicy.IsYoutubeSite(view.Source.Host))
                {
                    view.Reload();
                }
            }
            if (!productData.Settings.BlockYoutubeAds)
            {
                youtubeScriptLoaded = false;
                youtubeScriptInterventionCount = 0;
            }
            WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
        }

        private void BrowserWindowResize(object sender, EventArgs args)
        {
            if (WindowState == FormWindowState.Minimized && productData.Settings.MinimizeToTray)
            {
                BeginInvoke(new Action(HideToTray));
            }
        }

        private void HideToTray()
        {
            if (isClosing) return;
            trayIcon.Visible = true;
            Hide();
            ShowInTaskbar = false;
            if (!trayNoticeShown)
            {
                trayNoticeShown = true;
                trayIcon.BalloonTipTitle = "ZSEC Browser is still running";
                trayIcon.BalloonTipText = "Use the notification-area menu to restore or exit cleanly.";
                trayIcon.ShowBalloonTip(3500);
            }
        }

        private void RestoreFromTray()
        {
            if (isClosing) return;
            ShowInTaskbar = true;
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
            BringToFront();
        }

        private void BrowserWindowClosing(object sender, FormClosingEventArgs args)
        {
            if (!exitRequested && args.CloseReason == CloseReason.UserClosing && productData.Settings.CloseToTray)
            {
                args.Cancel = true;
                HideToTray();
                return;
            }
            isClosing = true;
            trayIcon.Visible = false;
            if (productData.Settings.ClearHistoryOnExit && CanPersistProductData(false))
            {
                try
                {
                    productStore.ClearHistory(productData);
                }
                catch
                {
                    // Shutdown must continue; no security state is relaxed by a history cleanup failure.
                }
            }
        }

        private void ExitBrowser()
        {
            exitRequested = true;
            trayIcon.Visible = false;
            Close();
        }

        private static string GetStartupDestination(BrowserSettings settings)
        {
            if (settings != null && settings.StartupMode == "new_tab") return Program.NewTabUri;
            if (settings != null && settings.StartupMode == "custom") return settings.CustomStartupUrl;
            return Program.DefaultStartPage;
        }

        private void PositionNewTabButton()
        {
            if (newTabButton == null || tabHost == null) return;
            int desiredLeft = 10;
            if (tabs.TabPages.Count > 0 && tabs.IsHandleCreated)
            {
                Rectangle last = tabs.GetTabRect(tabs.TabPages.Count - 1);
                desiredLeft = last.Right + 7;
            }
            newTabButton.Location = new Point(
                Math.Max(8, Math.Min(desiredLeft, Math.Max(8, tabHost.ClientSize.Width - newTabButton.Width - 12))),
                4
            );
            newTabButton.BringToFront();
        }

        private void DrawBrowserTab(object sender, DrawItemEventArgs args)
        {
            if (args.Index < 0 || args.Index >= tabs.TabPages.Count) return;
            Rectangle bounds = tabs.GetTabRect(args.Index);
            bounds.Inflate(-3, -3);
            bool selected = args.Index == tabs.SelectedIndex;
            Color fill = selected ? ElevatedSurface : PanelBackground;
            Color foreground = selected ? Foreground : Muted;
            using (GraphicsPath path = ModernUi.RoundedRectangle(bounds, 9))
            using (SolidBrush brush = new SolidBrush(fill))
            {
                args.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                args.Graphics.FillPath(brush, path);
                if (selected)
                {
                    using (Pen accentPen = new Pen(Accent, 1.5F))
                    {
                        args.Graphics.DrawPath(accentPen, path);
                    }
                }
            }

            Rectangle closeBounds = GetTabCloseBounds(bounds);
            Rectangle textBounds = new Rectangle(
                bounds.Left + 13,
                bounds.Top + 2,
                Math.Max(20, closeBounds.Left - bounds.Left - 18),
                bounds.Height - 4
            );
            TextRenderer.DrawText(
                args.Graphics,
                tabs.TabPages[args.Index].Text,
                tabs.Font,
                textBounds,
                foreground,
                TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix
            );
            using (Font closeFont = new Font("Segoe UI", 11F, FontStyle.Regular))
            {
                TextRenderer.DrawText(
                    args.Graphics,
                    "×",
                    closeFont,
                    closeBounds,
                    selected ? Foreground : Muted,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix
                );
            }
        }

        private static Rectangle GetTabCloseBounds(Rectangle tabBounds)
        {
            return new Rectangle(tabBounds.Right - 28, tabBounds.Top + 6, 20, Math.Max(18, tabBounds.Height - 12));
        }

        private void BrowserTabMouseDown(object sender, MouseEventArgs args)
        {
            for (int index = 0; index < tabs.TabPages.Count; index++)
            {
                Rectangle bounds = tabs.GetTabRect(index);
                bool closeClick = args.Button == MouseButtons.Left && GetTabCloseBounds(bounds).Contains(args.Location);
                bool middleClick = args.Button == MouseButtons.Middle && bounds.Contains(args.Location);
                if (!closeClick && !middleClick) continue;
                if (tabs.TabPages.Count == 1)
                {
                    tabs.SelectedIndex = index;
                    Navigate(Program.DefaultStartPage);
                }
                else
                {
                    CloseTabAt(index);
                }
                return;
            }
        }

        private async void InitializeBrowserAsync(object sender, EventArgs args)
        {
            try
            {
                WriteStartupStage("initialization_started");
                Directory.CreateDirectory(productRoot);
                Directory.CreateDirectory(profileRoot);
                RejectReparseDirectory(productRoot);
                RejectReparseDirectory(profileRoot);
                RejectReparseDirectory(extensionRoot);
                RejectReparseDirectory(newTabRoot);
                AssertRequiredRegularFile(Path.Combine(extensionRoot, "manifest.json"));
                AssertRequiredRegularFile(Path.Combine(newTabRoot, "index.html"));
                AssertRequiredRegularFile(youtubeProtectionPath);

                CoreWebView2EnvironmentOptions options = new CoreWebView2EnvironmentOptions();
                options.AdditionalBrowserArguments = "--enable-features=HttpsUpgrades";
                options.EnableTrackingPrevention = true;
                options.AreBrowserExtensionsEnabled = true;
                environment = await CoreWebView2Environment.CreateAsync(null, profileRoot, options);
                environment.NewBrowserVersionAvailable += delegate
                {
                    runtimeUpdateAvailable = true;
                    if (!IsDisposed && IsHandleCreated)
                    {
                        BeginInvoke(new Action(delegate
                        {
                            runtimeStatus.Text = "Security runtime update ready - restart ZSEC Browser";
                            WriteRuntimeEvidence(
                                CoreWebView2Environment.GetAvailableBrowserVersionString()
                            );
                        }));
                    }
                };
                WriteStartupStage("chromium_environment_ready");
                string runtimeVersion = CoreWebView2Environment.GetAvailableBrowserVersionString();
                runtimeStatus.Text = "Microsoft Chromium runtime " + runtimeVersion;
                await CreateTab(initialDestination, true);
                foreach (string additionalDestination in additionalDestinations)
                {
                    await CreateTab(additionalDestination, false);
                }
                WriteStartupStage("protected_tab_ready");
                shieldStatus.Text = "  SHIELDS: INSTALLED  ";
                shieldStatus.BackColor = Accent;
                environmentReady.TrySetResult(true);
                if (runtimeNewTabTest)
                {
                    await CreateNewTabCommandAsync("runtime_acceptance");
                }
                ClearStartupFailureEvidence();
                WriteRuntimeEvidence(runtimeVersion);
                WriteStartupStage("runtime_evidence_ready");
                if (!String.IsNullOrWhiteSpace(productDataWarning))
                {
                    runtimeStatus.Text = Truncate(productDataWarning, 140);
                }
            }
            catch (Exception exception)
            {
                WriteStartupStage("initialization_failed:" + exception.GetType().Name);
                environmentReady.TrySetException(exception);
                WriteStartupFailureEvidence(exception);
                runtimeStatus.Text = "Protection unavailable";
                shieldStatus.Text = "  STARTUP FAILED  ";
                shieldStatus.BackColor = Color.FromArgb(232, 73, 78);
                MessageBox.Show(
                    "ZSEC Browser failed closed before navigation.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                Close();
            }
        }

        private void ClearStartupFailureEvidence()
        {
            string path = Path.Combine(productRoot, "startup-failure.txt");
            if (File.Exists(path)) File.Delete(path);
        }

        private void WriteStartupFailureEvidence(Exception exception)
        {
            Directory.CreateDirectory(productRoot);
            string path = Path.Combine(productRoot, "startup-failure.txt");
            string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            string[] lines =
            {
                "schema=zsec.browser.startup-failure.v1",
                "product=ZSEC Browser",
                "version=" + Program.ProductVersion,
                "exception_type=" + exception.GetType().FullName,
                "hresult=0x" + exception.HResult.ToString("X8"),
                "message=" + exception.Message.Replace("\r", " ").Replace("\n", " "),
                "checked_at=" + DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            };
            File.WriteAllLines(temporary, lines, new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path);
        }

        private async Task<WebView2> CreateTab(
            string destination,
            bool select,
            bool navigate = true,
            bool deferRequestPolicy = false,
            bool allowShieldsSettings = false
        )
        {
            if (environment == null)
            {
                RecordTabCreationFailure("runtime_not_ready");
                throw new InvalidOperationException("The Microsoft Chromium runtime is still starting.");
            }
            if (tabs.TabPages.Count >= MaximumTabs)
            {
                RecordTabCreationFailure("tab_limit_rejected");
                throw new InvalidOperationException("The 32-tab safety limit has been reached.");
            }

            TabPage page = new TabPage("New tab");
            page.BackColor = Background;
            WebView2 view = new WebView2();
            view.Dock = DockStyle.Fill;
            view.BackColor = Background;
            view.DefaultBackgroundColor = Background;
            view.CreationProperties = new CoreWebView2CreationProperties();
            page.Controls.Add(view);
            tabs.TabPages.Add(page);
            browserViews.Add(view);
            PositionNewTabButton();
            if (select)
            {
                tabs.SelectedTab = page;
            }

            try
            {
                await view.EnsureCoreWebView2Async(environment);
                if (isClosing)
                {
                    throw new OperationCanceledException("The browser window is closing.");
                }
                await ConfigureWebViewAsync(view, page, allowShieldsSettings);
                if (isClosing)
                {
                    throw new OperationCanceledException("The browser window is closing.");
                }
                if (!deferRequestPolicy) AttachRequestPolicy(view);
                if (navigate) NavigateView(view, destination);
                lastTabAction = "opened";
                return view;
            }
            catch
            {
                RecordTabCreationFailure("open_failed");
                ReleaseLoginRequest(view);
                browserViews.Remove(view);
                tabs.TabPages.Remove(page);
                PositionNewTabButton();
                view.Dispose();
                page.Dispose();
                throw;
            }
        }

        private async Task CreateNewTabCommandAsync(string source)
        {
            WebView2 createdView = null;
            TabPage previousTab = null;
            await tabMutationGate.WaitAsync();
            try
            {
                if (isClosing) return;
                previousTab = tabs.SelectedTab;
                newTabButton.Enabled = false;
                runtimeStatus.Text = "Preparing protected tab...";
                protectionPulse.Active = true;
                await environmentReady.Task;
                createdView = await CreateTab(Program.DefaultStartPage, true, navigate: false);
                await NavigateUriAndWaitAsync(
                    createdView,
                    Program.NewTabUri,
                    "The packaged protected new tab"
                );
                address.Clear();
                address.Focus();
                lastTabAction = "new_tab_ready";
                lastNewTabCommandSource = source;
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            }
            catch (Exception exception)
            {
                RollBackFailedTab(createdView, previousTab);
                if (createdView != null) RecordTabCreationFailure("new_tab_navigation_failed");
                if (environment != null)
                {
                    WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
                }
                navigationProgress.Visible = false;
                protectionPulse.Active = false;
                runtimeStatus.Text = "New tab failed safely";
                if (!isClosing)
                {
                    MessageBox.Show(
                        "ZSEC Browser could not open the new tab.\r\n\r\n" + exception.Message,
                        "ZSEC Browser",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                }
            }
            finally
            {
                if (!IsDisposed) newTabButton.Enabled = true;
                tabMutationGate.Release();
            }
        }

        private async Task OpenShieldsSettingsAsync()
        {
            WebView2 createdView = null;
            TabPage previousTab = null;
            await tabMutationGate.WaitAsync();
            try
            {
                if (isClosing) return;
                previousTab = tabs.SelectedTab;
                string settingsUri = BuildShieldsSettingsUri();
                runtimeStatus.Text = "Opening verified Shields controls...";
                protectionPulse.Active = true;
                await environmentReady.Task;
                createdView = await CreateTab(
                    Program.DefaultStartPage,
                    true,
                    navigate: false,
                    deferRequestPolicy: false,
                    allowShieldsSettings: true
                );
                await NavigateUriAndWaitAsync(
                    createdView,
                    settingsUri,
                    "The verified Shields controls"
                );
                lastTabAction = "shields_controls_opened";
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            }
            catch (Exception exception)
            {
                RollBackFailedTab(createdView, previousTab);
                if (createdView != null)
                {
                    RecordTabCreationFailure("shields_controls_navigation_failed");
                }
                navigationProgress.Visible = false;
                protectionPulse.Active = false;
                runtimeStatus.Text = "Shields controls failed safely";
                if (!isClosing)
                {
                    MessageBox.Show(
                        "ZSEC Browser could not open the verified Shields controls.\r\n\r\n" + exception.Message,
                        "ZSEC Browser",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                }
            }
            finally
            {
                tabMutationGate.Release();
            }
        }

        private static async Task NavigateUriAndWaitAsync(
            WebView2 view,
            string uri,
            string description
        )
        {
            await NavigateAndWaitAsync(
                view,
                delegate { view.CoreWebView2.Navigate(uri); },
                description
            );
        }

        private static async Task NavigateAndWaitAsync(
            WebView2 view,
            Action navigate,
            string description
        )
        {
            ulong? expectedNavigationId = null;
            bool navigationIssued = false;
            TaskCompletionSource<CoreWebView2NavigationCompletedEventArgs> completion =
                new TaskCompletionSource<CoreWebView2NavigationCompletedEventArgs>(
                    TaskCreationOptions.RunContinuationsAsynchronously
                );
            EventHandler<CoreWebView2NavigationStartingEventArgs> startingHandler = null;
            startingHandler = delegate(object sender, CoreWebView2NavigationStartingEventArgs args)
            {
                if (navigationIssued && !expectedNavigationId.HasValue)
                {
                    expectedNavigationId = args.NavigationId;
                }
            };
            EventHandler<CoreWebView2NavigationCompletedEventArgs> completedHandler = null;
            completedHandler = delegate(object sender, CoreWebView2NavigationCompletedEventArgs args)
            {
                if (expectedNavigationId.HasValue && args.NavigationId == expectedNavigationId.Value)
                {
                    completion.TrySetResult(args);
                }
            };
            view.CoreWebView2.NavigationStarting += startingHandler;
            view.CoreWebView2.NavigationCompleted += completedHandler;
            try
            {
                navigationIssued = true;
                navigate();
                Task finished = await Task.WhenAny(completion.Task, Task.Delay(TimeSpan.FromSeconds(10)));
                if (finished != completion.Task)
                {
                    throw new TimeoutException(description + " did not become ready in time.");
                }
                CoreWebView2NavigationCompletedEventArgs result = await completion.Task;
                if (!result.IsSuccess)
                {
                    throw new InvalidOperationException(
                        description + " failed to load: " + result.WebErrorStatus
                    );
                }
            }
            finally
            {
                view.CoreWebView2.NavigationStarting -= startingHandler;
                view.CoreWebView2.NavigationCompleted -= completedHandler;
            }
        }

        private void RollBackFailedTab(WebView2 view, TabPage previousTab)
        {
            if (view != null)
            {
                TabPage page = view.Parent as TabPage;
                ReleaseLoginRequest(view);
                browserViews.Remove(view);
                if (page != null && tabs.TabPages.Contains(page)) tabs.TabPages.Remove(page);
                view.Dispose();
                if (page != null) page.Dispose();
            }
            if (previousTab != null && tabs.TabPages.Contains(previousTab))
            {
                tabs.SelectedTab = previousTab;
            }
            PositionNewTabButton();
        }

        private string BuildShieldsSettingsUri()
        {
            string site = "";
            WebView2 current = ActiveView;
            Uri source;
            if (current != null && current.Source != null &&
                Uri.TryCreate(current.Source.ToString(), UriKind.Absolute, out source) &&
                (source.Scheme == Uri.UriSchemeHttps || source.Scheme == Uri.UriSchemeHttp))
            {
                site = source.Host.TrimEnd('.').ToLowerInvariant();
            }
            string query = "?surface=tab";
            if (!String.IsNullOrWhiteSpace(site)) query += "&site=" + Uri.EscapeDataString(site);
            return ShieldsSettingsBaseUri + query;
        }

        private void RecordTabCreationFailure(string action)
        {
            tabCreationFailureCount++;
            lastTabAction = action;
            if (environment != null)
            {
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            }
        }

        private async Task ConfigureWebViewAsync(
            WebView2 view,
            TabPage page,
            bool allowShieldsSettings
        )
        {
            CoreWebView2 core = view.CoreWebView2;
            core.SetVirtualHostNameToFolderMapping(
                "newtab.zsec.local",
                newTabRoot,
                CoreWebView2HostResourceAccessKind.DenyCors
            );
            CoreWebView2Settings settings = core.Settings;
            settings.AreHostObjectsAllowed = false;
            settings.IsWebMessageEnabled = loginAssistant.Enabled;
            settings.IsPasswordAutosaveEnabled = false;
            settings.IsGeneralAutofillEnabled = false;
            settings.AreDefaultScriptDialogsEnabled = false;
            settings.AreDevToolsEnabled = false;
            settings.IsStatusBarEnabled = true;
            settings.AreDefaultContextMenusEnabled = true;
            core.Profile.PreferredTrackingPreventionLevel = CoreWebView2TrackingPreventionLevel.Balanced;
            effectiveTrackingPrevention = core.Profile.PreferredTrackingPreventionLevel
                .ToString()
                .ToLowerInvariant();
            await EnsureShieldsExtensionAsync(core.Profile);
            if (productData.Settings.BlockYoutubeAds)
            {
                string registration = await core.AddScriptToExecuteOnDocumentCreatedAsync(
                    youtubeProtectionSource
                );
                youtubeScriptRegistrations[view] = registration;
            }

            view.KeyDown += BrowserKeyDown;

            core.WebMessageReceived += delegate(
                object sender,
                CoreWebView2WebMessageReceivedEventArgs args
            )
            {
                HandleLoginMessage(view, args);
            };

            core.NavigationStarting += delegate(object sender, CoreWebView2NavigationStartingEventArgs args)
            {
                string previousLoginRequest;
                if (loginRequestIds.TryGetValue(view, out previousLoginRequest))
                    loginRequestTracker.Consume(previousLoginRequest);
                loginRequestIds.Remove(view);
                navigationProgress.Visible = true;
                protectionPulse.Active = true;
                runtimeStatus.Text = "Opening protected page...";
                HandleNavigationStarting(view, args, allowShieldsSettings);
            };
            core.FrameNavigationStarting += delegate(object sender, CoreWebView2NavigationStartingEventArgs args)
            {
                if (allowShieldsSettings)
                {
                    if (!IsAboutBlank(args.Uri) && !IsExpectedShieldsSettingsUri(args.Uri))
                    {
                        args.Cancel = true;
                    }
                    return;
                }
                if (!IsAllowedWebUri(args.Uri, false) && !IsAboutBlank(args.Uri))
                {
                    args.Cancel = true;
                }
            };
            core.SourceChanged += delegate
            {
                if (view == ActiveView)
                {
                    UpdateAddressFromActiveView();
                    UpdateBookmarkButton();
                }
            };
            core.DocumentTitleChanged += delegate
            {
                string title = core.DocumentTitle;
                page.Text = String.IsNullOrWhiteSpace(title) ? "New tab" : Truncate(title, 28);
                if (view == ActiveView) Text = page.Text + " - ZSEC Browser";
                if (String.Equals(title, "ZSEC DNR PASS", StringComparison.Ordinal))
                {
                    dnrRuntimeVerified = true;
                    WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
                }
            };
            core.NavigationCompleted += delegate(
                object sender,
                CoreWebView2NavigationCompletedEventArgs args
            )
            {
                navigationProgress.Visible = false;
                protectionPulse.Active = false;
                if (!args.IsSuccess)
                {
                    typedNavigationPending.Remove(view);
                    runtimeStatus.Text = "Navigation failed safely · " + args.WebErrorStatus;
                    lastNavigationHttps = false;
                    lastTabAction = "navigation_failed_" + args.WebErrorStatus.ToString().ToLowerInvariant();
                    WriteRuntimeEvidence(
                        CoreWebView2Environment.GetAvailableBrowserVersionString()
                    );
                    return;
                }
                runtimeStatus.Text = dnrRuntimeVerified
                    ? "Runtime ready · local DNR probe passed · Microsoft Chromium " +
                        CoreWebView2Environment.GetAvailableBrowserVersionString()
                    : "Runtime ready · Shields extension installed · Microsoft Chromium " +
                        CoreWebView2Environment.GetAvailableBrowserVersionString();
                lastNavigationHttps = view.Source != null &&
                    String.Equals(view.Source.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
                TryRecordHistory(view, core.DocumentTitle);
                if (view == ActiveView) UpdateBookmarkButton();
                if (view.Source != null && String.Equals(
                    view.Source.Host,
                    "newtab.zsec.local",
                    StringComparison.OrdinalIgnoreCase
                ))
                {
                    BeginInvoke(new Action(async delegate
                    {
                        await ApplyNewTabThemeAsync(view);
                    }));
                }
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
                if (loginAssistant.Enabled && view == ActiveView)
                {
                    BeginInvoke(new Action(async delegate
                    {
                        await ConfigureLoginPageAsync(view);
                    }));
                }
                if (view.Source != null && BrowserRequestPolicy.IsYoutubeSite(view.Source.Host))
                {
                    BeginInvoke(new Action(async delegate
                    {
                        await RefreshYoutubeProtectionStatusAsync(view);
                    }));
                }
            };
            core.NewWindowRequested += delegate(object sender, CoreWebView2NewWindowRequestedEventArgs args)
            {
                CoreWebView2Deferral deferral = args.GetDeferral();
                string requestedUri = args.Uri;
                bool userInitiated = args.IsUserInitiated;
                popupRequestCount++;
                if (!userInitiated || !IsAllowedPopupUri(requestedUri) || tabs.TabPages.Count >= MaximumTabs)
                {
                    args.Handled = true;
                    popupBlockedCount++;
                    lastTabAction = "popup_blocked";
                    WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
                    deferral.Complete();
                    return;
                }
                BeginInvoke(new Action(async delegate
                {
                    try
                    {
                        WebView2 popupView = await CreateTab(
                            Program.DefaultStartPage,
                            true,
                            false,
                            true
                        );
                        args.NewWindow = popupView.CoreWebView2;
                        AttachRequestPolicy(popupView);
                        args.Handled = true;
                        popupAllowedCount++;
                        lastTabAction = "popup_opened";
                    }
                    catch (Exception exception)
                    {
                        args.Handled = true;
                        popupBlockedCount++;
                        lastTabAction = "popup_failed";
                        navigationProgress.Visible = false;
                        runtimeStatus.Text = "Popup tab failed safely: " + Truncate(exception.Message, 90);
                    }
                    finally
                    {
                        WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
                        deferral.Complete();
                    }
                }));
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
            core.ContainsFullScreenElementChanged += delegate
            {
                BeginInvoke(new Action(delegate
                {
                    if (view == ActiveView)
                    {
                        SetFullScreen(core.ContainsFullScreenElement);
                    }
                }));
            };
            core.ProcessFailed += delegate
            {
                protectionPulse.Active = false;
                runtimeStatus.Text = "Renderer/runtime failure detected - reload this tab";
            };
        }

        private async Task ApplyNewTabThemeAsync(WebView2 view)
        {
            if (view == null || view.CoreWebView2 == null || view.Source == null) return;
            if (!String.Equals(view.Source.Host, "newtab.zsec.local", StringComparison.OrdinalIgnoreCase)) return;
            string script = "(()=>{const s=document.documentElement.style;" +
                "s.setProperty('--z-bg','" + ColorTranslator.ToHtml(Background) + "');" +
                "s.setProperty('--z-panel','" + ColorTranslator.ToHtml(PanelBackground) + "');" +
                "s.setProperty('--z-surface','" + ColorTranslator.ToHtml(ElevatedSurface) + "');" +
                "s.setProperty('--z-text','" + ColorTranslator.ToHtml(Foreground) + "');" +
                "s.setProperty('--z-muted','" + ColorTranslator.ToHtml(Muted) + "');" +
                "s.setProperty('--z-accent','" + ColorTranslator.ToHtml(Accent) + "');" +
                "s.setProperty('--z-border','" + ColorTranslator.ToHtml(theme.Border) + "');})();";
            await view.ExecuteScriptAsync(script);
        }

        private async Task ConfigureLoginPageAsync(WebView2 view)
        {
            if (view == null || view.CoreWebView2 == null || view.Source == null ||
                view != ActiveView || !loginAssistant.Enabled) return;
            string origin;
            try
            {
                origin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(view.Source);
            }
            catch (ArgumentException) { return; }
            if (String.Equals(view.Source.Host, "newtab.zsec.local", StringComparison.OrdinalIgnoreCase))
                return;

            if (productData.Settings.PasswordSaveEnabled &&
                !BrowserCredentialWorkflowPolicy.IsNeverSaveOrigin(productData.Settings, origin))
            {
                string previous;
                if (loginRequestIds.TryGetValue(view, out previous))
                    loginRequestTracker.Consume(previous);
                string requestId = loginRequestTracker.Issue();
                loginRequestIds[view] = requestId;
                await view.CoreWebView2.ExecuteScriptAsync(
                    loginAssistant.BuildCaptureScript(requestId, origin)
                );
            }

            if (!productData.Settings.PasswordAutofillEnabled) return;
            IList<BrowserVaultEntry> candidates;
            try { candidates = loginAssistant.CredentialsForOrigin(view.Source); }
            catch (Exception exception)
            {
                runtimeStatus.Text = "Saved logins are unavailable: " + Truncate(exception.Message, 80);
                return;
            }
            if (candidates.Count == 0) return;
            BrowserVaultEntry selected = candidates[0];
            if (candidates.Count > 1)
            {
                using (BrowserCredentialPickerDialog picker =
                    new BrowserCredentialPickerDialog(origin, candidates))
                {
                    if (picker.ShowDialog(this) != DialogResult.OK) return;
                    selected = picker.SelectedEntry;
                }
            }
            if (selected == null || view.Source == null || view != ActiveView) return;
            string currentOrigin;
            try { currentOrigin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(view.Source); }
            catch (ArgumentException) { return; }
            if (!String.Equals(currentOrigin, origin, StringComparison.Ordinal)) return;
            await view.CoreWebView2.ExecuteScriptAsync(
                loginAssistant.BuildFillScript(selected, currentOrigin)
            );
            runtimeStatus.Text = "Saved login filled for this exact HTTPS site.";
        }

        private void HandleLoginMessage(
            WebView2 view,
            CoreWebView2WebMessageReceivedEventArgs args
        )
        {
            if (view == null || view != ActiveView || view.Source == null ||
                !productData.Settings.PasswordSaveEnabled) return;
            string expected;
            if (!loginRequestIds.TryGetValue(view, out expected)) return;
            BrowserCredentialMessage message = loginAssistant.ParseCapture(
                args.WebMessageAsJson,
                args.Source,
                view.Source.AbsoluteUri
            );
            if (message == null ||
                !String.Equals(message.RequestId, expected, StringComparison.Ordinal) ||
                !loginRequestTracker.Consume(message.RequestId)) return;
            loginRequestIds.Remove(view);

            BrowserCredentialPromptPlan plan;
            try { plan = loginAssistant.EvaluateSave(message); }
            catch (Exception exception)
            {
                runtimeStatus.Text = "Password prompt unavailable: " + Truncate(exception.Message, 80);
                return;
            }
            if (plan.Kind == BrowserCredentialPromptKind.None) return;
            bool update = plan.Kind == BrowserCredentialPromptKind.Update;
            using (BrowserLoginSavePrompt prompt = new BrowserLoginSavePrompt(
                plan.Origin,
                message.Username,
                update
            ))
            {
                prompt.ShowDialog(this);
                if (prompt.Decision == BrowserLoginSaveDecision.NeverForSite)
                {
                    try
                    {
                        loginAssistant.NeverForOrigin(plan.Origin);
                        runtimeStatus.Text = "Password prompts disabled for this exact HTTPS site.";
                    }
                    catch (Exception exception)
                    {
                        runtimeStatus.Text = "Never-save preference failed: " +
                            Truncate(exception.Message, 80);
                    }
                    return;
                }
                if (prompt.Decision != BrowserLoginSaveDecision.Save) return;
            }
            try
            {
                loginAssistant.Save(
                    message,
                    plan,
                    update
                        ? BrowserCredentialPromptDecision.Update
                        : BrowserCredentialPromptDecision.Save
                );
                runtimeStatus.Text = update
                    ? "Saved password updated after confirmation."
                    : "Password saved after confirmation.";
            }
            catch (Exception exception)
            {
                runtimeStatus.Text = "Password was not saved: " + Truncate(exception.Message, 80);
            }
        }

        private void ApplyLoginAssistantSettings()
        {
            foreach (WebView2 view in browserViews.ToArray())
            {
                if (view.CoreWebView2 == null) continue;
                view.CoreWebView2.Settings.IsWebMessageEnabled = loginAssistant.Enabled;
                if (!loginAssistant.Enabled)
                {
                    string requestId;
                    if (loginRequestIds.TryGetValue(view, out requestId))
                        loginRequestTracker.Consume(requestId);
                    loginRequestIds.Remove(view);
                }
            }
            if (loginAssistant.Enabled && ActiveView != null)
            {
                BeginInvoke(new Action(async delegate
                {
                    await ConfigureLoginPageAsync(ActiveView);
                }));
            }
        }

        private void ReleaseLoginRequest(WebView2 view)
        {
            string requestId;
            if (view != null && loginRequestIds.TryGetValue(view, out requestId))
                loginRequestTracker.Consume(requestId);
            if (view != null) loginRequestIds.Remove(view);
        }

        private void AttachRequestPolicy(WebView2 view)
        {
            CoreWebView2 core = view.CoreWebView2;
            core.AddWebResourceRequestedFilter(
                "*",
                CoreWebView2WebResourceContext.All,
                CoreWebView2WebResourceRequestSourceKinds.All
            );
            core.WebResourceRequested += delegate(
                object sender,
                CoreWebView2WebResourceRequestedEventArgs args
            )
            {
                HandleWebResourceRequested(view, args);
            };
        }

        private async Task EnsureShieldsExtensionAsync(CoreWebView2Profile profile)
        {
            if (extensionInstallTask == null)
            {
                extensionInstallTask = InstallShieldsExtensionAsync(profile);
            }
            await extensionInstallTask;
        }

        private async Task InstallShieldsExtensionAsync(CoreWebView2Profile profile)
        {
            CoreWebView2BrowserExtension shields =
                await profile.AddBrowserExtensionAsync(extensionRoot);
            if (!String.Equals(shields.Id, ExpectedShieldsExtensionId, StringComparison.Ordinal) ||
                !String.Equals(shields.Name, "ZSEC Browser Shields", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The Browser Shields extension identity is invalid.");
            }
            if (!shields.IsEnabled)
            {
                await shields.EnableAsync(true);
            }
            IReadOnlyList<CoreWebView2BrowserExtension> installed =
                await profile.GetBrowserExtensionsAsync();
            string installedIdentitySummary = String.Join(
                ", ",
                installed.Select(extension =>
                    extension.Id + ":" + extension.Name + ":" +
                    (extension.IsEnabled ? "enabled" : "disabled")
                )
            );
            if (installed.Count(extension =>
                    String.Equals(extension.Id, ExpectedShieldsExtensionId, StringComparison.Ordinal) &&
                    extension.IsEnabled) != 1 ||
                installed.Any(extension => !IsExpectedBrowserExtension(extension)))
            {
                throw new InvalidOperationException(
                    "The browser profile contains an unexpected extension identity: " +
                    installedIdentitySummary
                );
            }
            shieldsExtensionEnabled = true;
            installedShieldsExtensionId = shields.Id;
        }

        private static bool IsExpectedBrowserExtension(CoreWebView2BrowserExtension extension)
        {
            if (String.Equals(extension.Id, ExpectedShieldsExtensionId, StringComparison.Ordinal))
            {
                return String.Equals(extension.Name, "ZSEC Browser Shields", StringComparison.Ordinal);
            }
            string expectedName;
            return ExpectedMicrosoftSystemExtensions.TryGetValue(extension.Id, out expectedName) &&
                String.Equals(extension.Name, expectedName, StringComparison.Ordinal);
        }

        private void HandleNavigationStarting(
            WebView2 view,
            CoreWebView2NavigationStartingEventArgs args,
            bool allowShieldsSettings
        )
        {
            Uri uri;
            if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out uri))
            {
                args.Cancel = true;
                navigationProgress.Visible = false;
                return;
            }

            if (IsAboutBlank(args.Uri))
            {
                return;
            }

            if (allowShieldsSettings)
            {
                if (IsExpectedShieldsSettingsUri(args.Uri)) return;
                args.Cancel = true;
                navigationProgress.Visible = false;
                ShowBlockedNotice("The verified Shields controls tab is locked to its extension origin.");
                return;
            }

            if (uri.Scheme == Uri.UriSchemeHttp)
            {
                args.Cancel = true;
                if (highRiskMode)
                {
                    navigationProgress.Visible = false;
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
                navigationProgress.Visible = false;
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

            string topLevelUrl = view.Source == null ? String.Empty : view.Source.AbsoluteUri;
            Uri probeTopLevel;
            if (args.ResourceContext == CoreWebView2WebResourceContext.Script &&
                Uri.TryCreate(topLevelUrl, UriKind.Absolute, out probeTopLevel) &&
                String.Equals(probeTopLevel.Host, "newtab.zsec.local", StringComparison.OrdinalIgnoreCase) &&
                String.Equals(requestUri.Host, "native-policy-probe.invalid", StringComparison.OrdinalIgnoreCase) &&
                String.Equals(requestUri.AbsolutePath, "/zsec-native-probe.js", StringComparison.Ordinal))
            {
                nativeSubresourceRuntimeProbePassed = true;
                BlockRequest(args);
                return;
            }
            if (productData.Settings.BlockYoutubeAds &&
                BrowserRequestPolicy.IsYoutubeAdRequest(topLevelUrl, requestUri.AbsoluteUri))
            {
                youtubeRequestBlockCount++;
                BlockRequest(args);
                return;
            }

            if (args.ResourceContext != CoreWebView2WebResourceContext.Document &&
                BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                    topLevelUrl,
                    requestUri.AbsoluteUri,
                    trackerDomains
                ))
            {
                nativeTrackerBlockCount++;
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
            blockedLabel.Text = "Native policy blocks: " + blockedRequestCount.ToString();
            WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
        }

        private bool RunNativePolicySelfTest()
        {
            const string YoutubePage = "https://www.youtube.com/watch?v=zsec-policy-probe";
            return BrowserRequestPolicy.IsYoutubeAdRequest(
                    YoutubePage,
                    "https://www.youtube.com/pagead/zsec-policy-probe"
                ) &&
                BrowserRequestPolicy.IsYoutubeAdRequest(
                    YoutubePage,
                    "https://static.doubleclick.net/instream/ad_status.js"
                ) &&
                !BrowserRequestPolicy.IsYoutubeAdRequest(
                    YoutubePage,
                    "https://www.youtube.com/youtubei/v1/player"
                ) &&
                BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                    "https://newtab.zsec.local/native-request-probe.html",
                    "https://doubleclick.net/zsec-native-probe.js",
                    trackerDomains
                ) &&
                !BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                    "https://www.youtube.com/watch?v=zsec-policy-probe",
                    "https://i.ytimg.com/vi/zsec-policy-probe/default.jpg",
                    trackerDomains
                );
        }

        private async Task RefreshYoutubeProtectionStatusAsync(WebView2 view)
        {
            if (youtubeStatusRefreshActive || view == null || view.CoreWebView2 == null ||
                view.Source == null || !BrowserRequestPolicy.IsYoutubeSite(view.Source.Host))
            {
                return;
            }
            youtubeStatusRefreshActive = true;
            try
            {
                string result = await view.CoreWebView2.ExecuteScriptAsync(
                    "globalThis.__zsecYoutubeProtection ? ({" +
                    "loaded:globalThis.__zsecYoutubeProtection.loaded," +
                    "removedFields:globalThis.__zsecYoutubeProtection.removedFields," +
                    "hiddenContainers:globalThis.__zsecYoutubeProtection.hiddenContainers," +
                    "skipControlsUsed:globalThis.__zsecYoutubeProtection.skipControlsUsed}) : null"
                );
                object parsed = new System.Web.Script.Serialization.JavaScriptSerializer()
                    .DeserializeObject(result);
                Dictionary<string, object> status = parsed as Dictionary<string, object>;
                if (status == null || !status.ContainsKey("loaded") ||
                    !Convert.ToBoolean(status["loaded"]))
                {
                    return;
                }
                youtubeScriptLoaded = true;
                int interventions = SafeStatusCount(status, "removedFields") +
                    SafeStatusCount(status, "hiddenContainers") +
                    SafeStatusCount(status, "skipControlsUsed");
                youtubeScriptInterventionCount = Math.Max(
                    youtubeScriptInterventionCount,
                    interventions
                );
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            }
            catch
            {
                // A page transition can invalidate script execution. The next bounded timer tick retries.
            }
            finally
            {
                youtubeStatusRefreshActive = false;
            }
        }

        private static int SafeStatusCount(Dictionary<string, object> status, string key)
        {
            object value;
            if (!status.TryGetValue(key, out value) || value == null) return 0;
            try
            {
                return Math.Max(0, Convert.ToInt32(value));
            }
            catch
            {
                return 0;
            }
        }

        private void TryRecordHistory(WebView2 view, string title)
        {
            if (!CanPersistProductData(false)) return;
            if (view == null || view.Source == null) return;
            string url = view.Source.AbsoluteUri;
            if (!IsAllowedWebUri(url, true) ||
                String.Equals(url, Program.NewTabUri, StringComparison.OrdinalIgnoreCase) ||
                IsExpectedShieldsSettingsUri(url))
            {
                return;
            }
            try
            {
                bool typed = typedNavigationPending.Remove(view);
                productStore.AddHistory(productData, title, url, typed);
                RefreshAddressSuggestions();
            }
            catch (Exception exception)
            {
                runtimeStatus.Text = "History was not saved: " + Truncate(exception.Message, 90);
            }
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

            if (productData.Settings.AskDownloadLocation)
            {
                SaveFileDialog picker = new SaveFileDialog();
                picker.FileName = suggestedName;
                picker.InitialDirectory = Directory.Exists(productData.Settings.DownloadDirectory)
                    ? productData.Settings.DownloadDirectory
                    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                picker.OverwritePrompt = true;
                if (picker.ShowDialog(this) != DialogResult.OK)
                {
                    args.Cancel = true;
                    return;
                }
                args.ResultFilePath = picker.FileName;
            }
            else
            {
                try
                {
                    args.ResultFilePath = GetAvailableDownloadPath(
                        productData.Settings.DownloadDirectory,
                        suggestedName
                    );
                }
                catch (Exception exception)
                {
                    args.Cancel = true;
                    MessageBox.Show(
                        "The approved download was cancelled because the configured folder is unavailable.\r\n\r\n" +
                            exception.Message,
                        "ZSEC Browser",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                }
            }
        }

        private static string GetAvailableDownloadPath(string directory, string fileName)
        {
            string root = Path.GetFullPath(directory);
            Directory.CreateDirectory(root);
            RejectReparseDirectory(root);
            string safeName = SanitizeFileName(fileName);
            string candidate = Path.Combine(root, safeName);
            if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
            string stem = Path.GetFileNameWithoutExtension(safeName);
            string extension = Path.GetExtension(safeName);
            for (int index = 1; index <= 9999; index++)
            {
                candidate = Path.Combine(root, stem + " (" + index.ToString() + ")" + extension);
                if (!File.Exists(candidate) && !Directory.Exists(candidate)) return candidate;
            }
            throw new IOException("No available download file name could be allocated.");
        }

        private void AddressKeyDown(object sender, KeyEventArgs args)
        {
            if (args.KeyCode == Keys.Enter)
            {
                args.SuppressKeyPress = true;
                if (ActiveView != null) typedNavigationPending.Add(ActiveView);
                Navigate(Program.ResolveDestination(
                    new[] { address.Text },
                    productData.Settings.SearchEngine
                ));
            }
        }

        private void BrowserKeyDown(object sender, KeyEventArgs args)
        {
            if (args.Control && args.KeyCode == Keys.L)
            {
                args.SuppressKeyPress = true;
                args.Handled = true;
                BeginInvoke(new Action(delegate { address.Focus(); address.SelectAll(); }));
            }
            else if (args.Control && args.KeyCode == Keys.T)
            {
                args.SuppressKeyPress = true;
                args.Handled = true;
                BeginInvoke(new Action(delegate { CreateTabFromKeyboardAsync(); }));
            }
            else if (args.Control && args.KeyCode == Keys.R)
            {
                args.SuppressKeyPress = true;
                args.Handled = true;
                BeginInvoke(new Action(delegate { if (ActiveView != null) ActiveView.Reload(); }));
            }
            else if (args.Control && args.KeyCode == Keys.W && tabs.TabPages.Count > 1)
            {
                args.SuppressKeyPress = true;
                args.Handled = true;
                BeginInvoke(new Action(CloseActiveTab));
            }
            else if (args.Alt && args.KeyCode == Keys.Left)
            {
                args.SuppressKeyPress = true;
                args.Handled = true;
                BeginInvoke(new Action(delegate { if (ActiveView != null && ActiveView.CanGoBack) ActiveView.GoBack(); }));
            }
            else if (args.Alt && args.KeyCode == Keys.Right)
            {
                args.SuppressKeyPress = true;
                args.Handled = true;
                BeginInvoke(new Action(delegate { if (ActiveView != null && ActiveView.CanGoForward) ActiveView.GoForward(); }));
            }
        }

        protected override bool ProcessCmdKey(ref Message message, Keys keyData)
        {
            if (keyData == Keys.F11)
            {
                SetFullScreen(!isFullScreen);
                return true;
            }
            if (keyData == Keys.Escape && isFullScreen)
            {
                SetFullScreen(false);
                return true;
            }
            if (keyData == (Keys.Control | Keys.L))
            {
                address.Focus();
                address.SelectAll();
                return true;
            }
            if (keyData == (Keys.Control | Keys.T))
            {
                CreateTabFromKeyboardAsync();
                return true;
            }
            if (keyData == (Keys.Control | Keys.W))
            {
                if (tabs.TabPages.Count > 1) CloseActiveTab();
                return true;
            }
            if (keyData == (Keys.Control | Keys.R))
            {
                if (ActiveView != null) ActiveView.Reload();
                return true;
            }
            if (keyData == (Keys.Control | Keys.D))
            {
                AddActiveBookmark(this, EventArgs.Empty);
                return true;
            }
            if (keyData == (Keys.Control | Keys.Shift | Keys.B))
            {
                ToggleBookmarksBar(this, EventArgs.Empty);
                return true;
            }
            if (keyData == (Keys.Control | Keys.Shift | Keys.O))
            {
                ShowBookmarksManager();
                return true;
            }
            if (keyData == (Keys.Control | Keys.H))
            {
                ShowHistory();
                return true;
            }
            if (keyData == (Keys.Control | Keys.Shift | Keys.Delete))
            {
                ClearBrowsingHistory();
                return true;
            }
            if (keyData == (Keys.Control | Keys.Shift | Keys.P))
            {
                ShowPasswords();
                return true;
            }
            if (keyData == (Keys.Control | Keys.Oemcomma))
            {
                BeginInvoke(new Action(async delegate { await ShowSettingsAsync(); }));
                return true;
            }
            if (keyData == (Keys.Alt | Keys.F))
            {
                ShowMainMenu();
                return true;
            }
            if (keyData == Keys.F6)
            {
                address.Focus();
                address.SelectAll();
                return true;
            }
            if (keyData == (Keys.Control | Keys.Tab))
            {
                SelectRelativeTab(1);
                return true;
            }
            if (keyData == (Keys.Control | Keys.Shift | Keys.Tab))
            {
                SelectRelativeTab(-1);
                return true;
            }
            if (keyData == (Keys.Alt | Keys.Left))
            {
                if (ActiveView != null && ActiveView.CanGoBack) ActiveView.GoBack();
                return true;
            }
            if (keyData == (Keys.Alt | Keys.Right))
            {
                if (ActiveView != null && ActiveView.CanGoForward) ActiveView.GoForward();
                return true;
            }
            return base.ProcessCmdKey(ref message, keyData);
        }

        private void SetFullScreen(bool enabled)
        {
            if (enabled == isFullScreen) return;
            isFullScreen = enabled;
            if (enabled)
            {
                fullScreenControlVisibility.Clear();
                foreach (Control control in Controls)
                {
                    if (control == tabHost) continue;
                    fullScreenControlVisibility[control] = control.Visible;
                    control.Visible = false;
                }
                windowedBorderStyle = FormBorderStyle;
                windowedState = WindowState;
                windowedTabItemSize = tabs.ItemSize;
                FormBorderStyle = FormBorderStyle.None;
                WindowState = FormWindowState.Maximized;
                tabs.ItemSize = new Size(tabs.ItemSize.Width, 1);
                newTabButton.Visible = false;
                runtimeStatus.Text = "Fullscreen media · F11 or Esc to exit";
                return;
            }

            FormBorderStyle = windowedBorderStyle;
            WindowState = windowedState;
            tabs.ItemSize = windowedTabItemSize;
            newTabButton.Visible = true;
            foreach (KeyValuePair<Control, bool> entry in fullScreenControlVisibility)
            {
                entry.Key.Visible = entry.Value;
            }
            fullScreenControlVisibility.Clear();
            PositionNewTabButton();
            runtimeStatus.Text = "Runtime ready · Microsoft Chromium " +
                CoreWebView2Environment.GetAvailableBrowserVersionString();
        }

        private void SelectRelativeTab(int delta)
        {
            if (tabs.TabPages.Count <= 1) return;
            int current = Math.Max(0, tabs.SelectedIndex);
            int next = (current + delta + tabs.TabPages.Count) % tabs.TabPages.Count;
            tabs.SelectedIndex = next;
        }

        private void Navigate(string destination)
        {
            if (ActiveView != null) NavigateView(ActiveView, destination);
        }

        private async void CreateTabFromKeyboardAsync()
        {
            await CreateNewTabCommandAsync("keyboard");
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
            if (!CanPersistProductData(true)) return;
            bool requested = !highRiskMode;
            productData.Settings.NativeStrictMode = requested;
            try
            {
                productStore.Save(productData);
                highRiskMode = requested;
            }
            catch (Exception exception)
            {
                productData.Settings.NativeStrictMode = highRiskMode;
                MessageBox.Show(
                    "The native guard setting was not changed.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
                return;
            }
            LayoutNavigationToolbar();
            highRiskButton.Checked = highRiskMode;
            highRiskButton.BackColor = highRiskMode ? Color.FromArgb(210, 74, 54) : PanelBackground;
            runtimeStatus.Text = highRiskMode
                ? "Strict native navigation policy enabled"
                : "Standard native navigation policy enabled";
            WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
        }

        private void ShowAbout(object sender, EventArgs args)
        {
            string runtime = environment == null ? "not initialized" : CoreWebView2Environment.GetAvailableBrowserVersionString();
            MessageBox.Show(
                "ZSEC Browser Community " + Program.ProductVersion + "\r\n\r\n" +
                "Engine: Microsoft Edge WebView2 (Chromium) " + runtime + "\r\n" +
                "Protection: Browser Shields MV3 + separate native strict policy\r\n" +
                "Policy provenance: " + trackerDomains.Count + " reviewed domains, " + trackingParameters.Count + " tracking parameters\r\n" +
                "Tracking prevention: Balanced\r\n" +
                "YouTube native protection: " +
                    (productData.Settings.BlockYoutubeAds ? "enabled" : "disabled") +
                    "; hook " + (youtubeScriptLoaded ? "observed" : "not yet observed") + "\r\n" +
                "Bookmarks/history: local per-user storage; no ZSEC cloud sync\r\n" +
                "Address search: " + BrowserSearchProviders.DisplayName(productData.Settings.SearchEngine) + "\r\n" +
                "Tray: native notification-area lifecycle with explicit exit\r\n" +
                "Profile: separate app data under LocalAppData\r\n" +
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
            if (tabs.SelectedIndex < 0) return;
            CloseTabAt(tabs.SelectedIndex);
        }

        private void CloseTabAt(int index)
        {
            if (index < 0 || index >= tabs.TabPages.Count) return;
            TabPage page = tabs.TabPages[index];
            WebView2 view = page.Controls.Count > 0 ? page.Controls[0] as WebView2 : null;
            if (view != null)
            {
                ReleaseLoginRequest(view);
                browserViews.Remove(view);
                youtubeScriptRegistrations.Remove(view);
                typedNavigationPending.Remove(view);
                view.Dispose();
            }
            tabs.TabPages.RemoveAt(index);
            page.Dispose();
            PositionNewTabButton();
            if (environment != null)
            {
                lastTabAction = "closed";
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
            }
            if (tabs.TabPages.Count == 0)
            {
                CreateTabFromKeyboardAsync();
            }
        }

        private void UpdateAddressFromActiveView()
        {
            if (ActiveView != null && ActiveView.Source != null)
            {
                string source = ActiveView.Source.AbsoluteUri;
                address.Text = String.Equals(source, Program.NewTabUri, StringComparison.OrdinalIgnoreCase) ||
                    IsExpectedShieldsSettingsUri(source)
                    ? String.Empty
                    : source;
            }
            else address.Clear();
            UpdateBookmarkButton();
        }

        private void RefreshAddressSuggestions()
        {
            AutoCompleteStringCollection suggestions = new AutoCompleteStringCollection();
            suggestions.AddRange(productStore
                .GetAddressSuggestions(productData, String.Empty, 1200)
                .ToArray());
            address.AutoCompleteCustomSource = suggestions;
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

        private static bool IsAllowedPopupUri(string candidate)
        {
            return String.IsNullOrWhiteSpace(candidate) ||
                IsAboutBlank(candidate) ||
                IsAllowedWebUri(candidate, true);
        }

        private static bool IsAboutBlank(string candidate)
        {
            return String.Equals(candidate, "about:blank", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsExpectedShieldsSettingsUri(string candidate)
        {
            Uri uri;
            if (!Uri.TryCreate(candidate, UriKind.Absolute, out uri)) return false;
            if (!String.Equals(uri.Scheme, "chrome-extension", StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(uri.Host, ExpectedShieldsExtensionId, StringComparison.Ordinal) ||
                !String.Equals(uri.AbsolutePath, "/popup/index.html", StringComparison.Ordinal) ||
                !String.IsNullOrEmpty(uri.Fragment))
            {
                return false;
            }
            System.Collections.Specialized.NameValueCollection query = HttpUtility.ParseQueryString(uri.Query);
            if (!String.Equals(query["surface"], "tab", StringComparison.Ordinal)) return false;
            foreach (string key in query.AllKeys)
            {
                if (!String.Equals(key, "surface", StringComparison.Ordinal) &&
                    !String.Equals(key, "site", StringComparison.Ordinal))
                {
                    return false;
                }
            }
            string site = query["site"];
            return String.IsNullOrEmpty(site) ||
                (site.Length <= 253 &&
                 site.IndexOf("..", StringComparison.Ordinal) < 0 &&
                 site.All(character => Char.IsLetterOrDigit(character) || character == '.' || character == '-'));
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

        private static void AssertRequiredRegularFile(string path)
        {
            FileInfo file = new FileInfo(path);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException("Required ZSEC file is missing or unsafe: " + path);
            }
        }

        private static string ComputeSha256RegularFile(string path)
        {
            AssertRequiredRegularFile(path);
            using (FileStream stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read
            ))
            using (SHA256 digest = SHA256.Create())
            {
                return String.Concat(digest.ComputeHash(stream).Select(value => value.ToString("x2")));
            }
        }

        private static string ReadBoundedRegularText(string path, int maximumBytes)
        {
            AssertRequiredRegularFile(path);
            FileInfo file = new FileInfo(path);
            if (file.Length <= 0 || file.Length > maximumBytes)
            {
                throw new InvalidDataException("A required ZSEC script has an invalid size.");
            }
            return File.ReadAllText(path, new UTF8Encoding(false, true));
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
                "browser_shields_extension=" + (shieldsExtensionEnabled ? "enabled" : "unavailable"),
                "browser_shields_expected_id=" + ExpectedShieldsExtensionId,
                "browser_shields_installed_id=" + installedShieldsExtensionId,
                "browser_shields_manifest_sha256=" + extensionManifestSha256,
                "dnr_runtime_test_status=" + (dnrRuntimeVerified ? "passed" : "not_run"),
                "runtime_update_available=" + runtimeUpdateAvailable.ToString().ToLowerInvariant(),
                "tracking_prevention_requested=balanced",
                "tracking_prevention_effective=" + effectiveTrackingPrevention,
                "youtube_ui_assist=" + (shieldsExtensionEnabled ? "enabled_best_effort" : "unavailable"),
                "native_request_filter_source_kinds=all",
                "native_reviewed_tracker_blocking=enabled",
                "native_tracker_policy_self_test_status=" + (nativePolicySelfTestPassed ? "passed" : "failed"),
                "native_subresource_runtime_probe_status=" + (nativeSubresourceRuntimeProbePassed ? "passed" : "not_run"),
                "youtube_native_protection_enabled=" + productData.Settings.BlockYoutubeAds.ToString().ToLowerInvariant(),
                "youtube_protection_script_sha256=" + youtubeProtectionSha256,
                "youtube_protection_hook_status=" + (!productData.Settings.BlockYoutubeAds
                    ? "disabled_by_user"
                    : youtubeScriptLoaded ? "loaded" : "not_observed"),
                "youtube_request_block_count=" + youtubeRequestBlockCount.ToString(),
                "youtube_script_intervention_count=" + youtubeScriptInterventionCount.ToString(),
                "youtube_ad_intervention_count=" + (youtubeRequestBlockCount + youtubeScriptInterventionCount).ToString(),
                "host_filter_source_kinds=all",
                "request_count_coverage=all_web_resource_source_kinds",
                "profile_separate=true",
                "sandbox_attestation_complete=false",
                "tab_count=" + tabs.TabPages.Count.ToString(),
                "ready_tab_count=" + browserViews.Count(view => view.CoreWebView2 != null).ToString(),
                "popup_request_count=" + popupRequestCount.ToString(),
                "popup_allowed_count=" + popupAllowedCount.ToString(),
                "popup_blocked_count=" + popupBlockedCount.ToString(),
                "tab_creation_failure_count=" + tabCreationFailureCount.ToString(),
                "last_tab_action=" + lastTabAction,
                "last_new_tab_command_source=" + lastNewTabCommandSource,
                "high_risk_mode=" + highRiskMode.ToString().ToLowerInvariant(),
                "bookmarks_count=" + productData.Bookmarks.Count.ToString(),
                "history_count=" + productData.History.Count.ToString(),
                "history_recording_enabled=" + productData.Settings.RecordHistory.ToString().ToLowerInvariant(),
                "address_history_suggestions_enabled=true",
                "search_engine=" + BrowserSearchProviders.NormalizeKey(productData.Settings.SearchEngine),
                "clear_history_on_exit=" + productData.Settings.ClearHistoryOnExit.ToString().ToLowerInvariant(),
                "bookmarks_bar_visible=" + bookmarksBar.Visible.ToString().ToLowerInvariant(),
                "minimize_to_tray_enabled=" + productData.Settings.MinimizeToTray.ToString().ToLowerInvariant(),
                "close_to_tray_enabled=" + productData.Settings.CloseToTray.ToString().ToLowerInvariant(),
                "download_location_prompt=" + productData.Settings.AskDownloadLocation.ToString().ToLowerInvariant(),
                "default_browser_registration_supported=false",
                "blocked_request_count=" + blockedRequestCount.ToString(),
                "native_tracker_block_count=" + nativeTrackerBlockCount.ToString(),
                "tracking_cleanup_count=" + trackingCleanupCount.ToString(),
                "last_navigation_https=" + lastNavigationHttps.ToString().ToLowerInvariant(),
                "host_objects_allowed=false",
                "web_messages_enabled=" + (loginAssistant.Enabled
                    ? "bounded_login_assistant_only"
                    : "false"),
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

        private void WriteStartupStage(string stage)
        {
            try
            {
                Directory.CreateDirectory(productRoot);
                string path = Path.Combine(productRoot, "startup-state.txt");
                string value = String.Join(
                    Environment.NewLine,
                    new[]
                    {
                        "schema=zsec.browser.startup-state.v1",
                        "version=" + Program.ProductVersion,
                        "stage=" + stage.Replace("\r", " ").Replace("\n", " "),
                        "process_id=" + Process.GetCurrentProcess().Id.ToString(),
                        "checked_at=" + DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    }
                ) + Environment.NewLine;
                File.WriteAllText(path, value, new UTF8Encoding(false));
            }
            catch
            {
                // Startup diagnostics must never become a startup dependency.
            }
        }

        private void DisposeBrowserViews(object sender, FormClosedEventArgs args)
        {
            try { vaultService.Lock(); } catch (Exception) { }
            IDisposable disposableVault = vaultService as IDisposable;
            if (disposableVault != null) disposableVault.Dispose();
            youtubeStatusTimer.Stop();
            youtubeStatusTimer.Dispose();
            trayIcon.Visible = false;
            trayIcon.Dispose();
            mainMenu.Dispose();
            foreach (WebView2 view in browserViews.ToArray()) view.Dispose();
            browserViews.Clear();
            youtubeScriptRegistrations.Clear();
            typedNavigationPending.Clear();
            loginRequestIds.Clear();
            loginRequestTracker.Clear();
            tabMutationGate.Dispose();
        }
    }
}
