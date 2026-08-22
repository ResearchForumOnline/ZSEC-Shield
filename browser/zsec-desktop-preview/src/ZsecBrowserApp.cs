using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
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
[assembly: AssemblyVersion("0.3.6.0")]
[assembly: AssemblyFileVersion("0.3.6.0")]
[assembly: AssemblyInformationalVersion("0.3.6-community")]

namespace TalkToAI.ZsecBrowserPreview
{
    internal static class Program
    {
        internal const string ProductName = "ZSEC Browser";
        internal const string ProductVersion = "0.3.6";
        internal const string DefaultStartPage = "https://talktoai.org/zero-browser/";
        internal const string NewTabUri = "https://newtab.zsec.local/index.html";

        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string destination = ResolveDestination(args);
            try
            {
                bool runtimeNewTabTest = args.Any(value =>
                    String.Equals(
                        value,
                        "--zsec-runtime-test=new-tab",
                        StringComparison.OrdinalIgnoreCase
                    )
                );
                Application.Run(new BrowserWindow(destination, runtimeNewTabTest));
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
        internal int CornerRadius { get; set; }

        internal RoundedSurface()
        {
            DoubleBuffered = true;
            SurfaceColor = Color.FromArgb(17, 35, 44);
            BorderColor = Color.FromArgb(44, 73, 84);
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
            using (Pen pen = new Pen(BorderColor, 1F))
            {
                args.Graphics.FillPath(brush, path);
                args.Graphics.DrawPath(pen, path);
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
        private static readonly Color Background = Color.FromArgb(4, 12, 18);
        private static readonly Color PanelBackground = Color.FromArgb(9, 24, 31);
        private static readonly Color ElevatedSurface = Color.FromArgb(15, 34, 43);
        private static readonly Color HoverSurface = Color.FromArgb(24, 52, 63);
        private static readonly Color Accent = Color.FromArgb(0, 229, 170);
        private static readonly Color AccentBlue = Color.FromArgb(35, 174, 232);
        private static readonly Color Muted = Color.FromArgb(151, 170, 181);
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
        private readonly string applicationRoot;
        private readonly string productRoot;
        private readonly string profileRoot;
        private readonly string policyRoot;
        private readonly string extensionRoot;
        private readonly string newTabRoot;
        private readonly string extensionManifestSha256;
        private readonly HashSet<string> trackerDomains;
        private readonly HashSet<string> trackingParameters;
        private readonly List<WebView2> browserViews;
        private readonly TabControl tabs;
        private readonly Panel tabHost;
        private readonly RoundedActionButton newTabButton;
        private readonly TextBox address;
        private readonly ToolStripControlHost addressHost;
        private readonly Label shieldStatus;
        private readonly Label runtimeStatus;
        private readonly ProtectionPulse protectionPulse;
        private readonly ToolStripButton highRiskButton;
        private readonly ToolStripLabel blockedLabel;
        private readonly ToolStripProgressBar navigationProgress;
        private CoreWebView2Environment environment;
        private int blockedRequestCount;
        private int trackingCleanupCount;
        private bool highRiskMode;
        private bool lastNavigationHttps;
        private bool shieldsExtensionEnabled;
        private bool dnrRuntimeVerified;
        private bool runtimeUpdateAvailable;
        private bool isClosing;
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

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(
            IntPtr window,
            int attribute,
            ref int value,
            int valueSize
        );

        internal BrowserWindow(string destination, bool testNewTab = false)
        {
            initialDestination = destination;
            runtimeNewTabTest = testNewTab;
            applicationRoot = AppDomain.CurrentDomain.BaseDirectory;
            productRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "TalkToAI",
                "ZSEC Browser"
            );
            profileRoot = Path.Combine(productRoot, "User Data");
            policyRoot = Path.Combine(applicationRoot, "policy");
            extensionRoot = Path.Combine(applicationRoot, "extension");
            newTabRoot = Path.Combine(applicationRoot, "new-tab");
            extensionManifestSha256 = ComputeSha256RegularFile(
                Path.Combine(extensionRoot, "manifest.json")
            );
            trackerDomains = LoadRequiredLines(Path.Combine(policyRoot, "tracker-domains.txt"));
            trackingParameters = LoadRequiredLines(Path.Combine(policyRoot, "tracking-parameters.txt"));
            browserViews = new List<WebView2>();
            environmentReady = new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously
            );
            tabMutationGate = new SemaphoreSlim(1, 1);

            Text = "ZSEC Browser";
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            StartPosition = FormStartPosition.CenterScreen;
            WindowState = FormWindowState.Maximized;
            MinimumSize = new Size(960, 640);
            BackColor = Background;
            ForeColor = Color.White;
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
            channel.Text = "COMMUNITY 0.3.6";
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

            ToolStrip navigation = new ToolStrip();
            navigation.Dock = DockStyle.Top;
            navigation.GripStyle = ToolStripGripStyle.Hidden;
            navigation.RenderMode = ToolStripRenderMode.Professional;
            navigation.Renderer = new ModernToolStripRenderer(HoverSurface, Color.FromArgb(30, 74, 83));
            navigation.BackColor = PanelBackground;
            navigation.ForeColor = Color.White;
            navigation.Padding = new Padding(12, 8, 12, 8);
            navigation.ImageScalingSize = new Size(20, 20);
            navigation.AutoSize = false;
            navigation.Height = 54;

            ToolStripButton backButton = CreateButton("‹", "Back (Alt+Left)", delegate { if (ActiveView != null && ActiveView.CanGoBack) ActiveView.GoBack(); });
            ToolStripButton forwardButton = CreateButton("›", "Forward (Alt+Right)", delegate { if (ActiveView != null && ActiveView.CanGoForward) ActiveView.GoForward(); });
            ToolStripButton reloadButton = CreateButton("↻", "Reload (Ctrl+R)", delegate { if (ActiveView != null) ActiveView.Reload(); });
            ToolStripButton homeButton = CreateButton("⌂", "ZSEC home", delegate { Navigate(Program.DefaultStartPage); });

            RoundedSurface addressSurface = new RoundedSurface();
            addressSurface.Size = new Size(660, 36);
            addressSurface.SurfaceColor = ElevatedSurface;
            addressSurface.BorderColor = Color.FromArgb(42, 75, 88);
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
            address.KeyDown += AddressKeyDown;
            addressSurface.Controls.Add(address);
            addressHost = new ToolStripControlHost(addressSurface);
            addressHost.AutoSize = false;
            addressHost.Width = 660;
            addressHost.Height = 38;
            addressHost.Margin = new Padding(7, 0, 7, 0);

            highRiskButton = CreateButton("Native guard: Standard", "Toggle stricter native navigation policy", ToggleHighRiskMode);
            highRiskButton.CheckOnClick = false;
            ToolStripButton shieldsButton = CreateButton("Shields", "Open ZSEC Browser Shields controls", async delegate { await OpenShieldsSettingsAsync(); });
            ToolStripButton aboutButton = CreateButton("⋯", "About ZSEC Browser", ShowAbout);

            navigation.Items.AddRange(new ToolStripItem[]
            {
                backButton,
                forwardButton,
                reloadButton,
                homeButton,
                addressHost,
                new ToolStripSeparator(),
                highRiskButton,
                shieldsButton,
                aboutButton
            });
            navigation.Resize += delegate
            {
                int reserved = 520;
                addressHost.Width = Math.Max(280, navigation.ClientSize.Width - reserved);
                addressSurface.Width = addressHost.Width;
            };

            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.Font = new Font("Segoe UI Semibold", 9F);
            tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            tabs.ItemSize = new Size(210, 36);
            tabs.SizeMode = TabSizeMode.Fixed;
            tabs.Padding = new Point(18, 5);
            tabs.HotTrack = true;
            tabs.DrawItem += DrawBrowserTab;
            tabs.MouseDown += BrowserTabMouseDown;
            tabs.SelectedIndexChanged += delegate
            {
                UpdateAddressFromActiveView();
                PositionNewTabButton();
            };

            tabHost = new Panel();
            tabHost.Dock = DockStyle.Fill;
            tabHost.BackColor = Background;
            tabHost.Controls.Add(tabs);
            newTabButton = new RoundedActionButton();
            newTabButton.Text = "+";
            newTabButton.Font = new Font("Segoe UI", 15F, FontStyle.Regular);
            newTabButton.ForeColor = Color.White;
            newTabButton.Size = new Size(38, 30);
            newTabButton.AccessibleName = "New tab";
            newTabButton.AccessibleDescription = "Open a protected local new tab (Ctrl+T)";
            newTabButton.Click += async delegate { await CreateNewTabCommandAsync("tab_strip"); };
            tabHost.Controls.Add(newTabButton);
            newTabButton.BringToFront();
            tabHost.Resize += delegate { PositionNewTabButton(); };

            StatusStrip status = new StatusStrip();
            status.BackColor = PanelBackground;
            status.ForeColor = Muted;
            runtimeStatus = new Label();
            runtimeStatus.Text = "Starting Microsoft Chromium runtime...";
            runtimeStatus.ForeColor = Muted;
            runtimeStatus.AutoSize = true;
            ToolStripControlHost runtimeHost = new ToolStripControlHost(runtimeStatus);
            blockedLabel = new ToolStripLabel("Native policy blocks: 0");
            blockedLabel.ForeColor = Accent;
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

            Controls.Add(tabHost);
            Controls.Add(status);
            Controls.Add(navigation);
            Controls.Add(brandBar);

            Load += InitializeBrowserAsync;
            FormClosing += delegate { isClosing = true; };
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
            button.ForeColor = Color.White;
            button.Font = new Font("Segoe UI Symbol", text.Length <= 2 ? 14F : 9F, FontStyle.Bold);
            button.AutoSize = false;
            button.Size = new Size(text.Length > 2 ? 118 : 42, 34);
            button.Margin = new Padding(2, 0, 2, 0);
            button.ToolTipText = toolTip;
            button.AccessibleName = toolTip;
            button.Click += handler;
            return button;
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
            Color foreground = selected ? Color.White : Muted;
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
                    selected ? Color.White : Muted,
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
            settings.IsWebMessageEnabled = false;
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

            view.KeyDown += BrowserKeyDown;

            core.NavigationStarting += delegate(object sender, CoreWebView2NavigationStartingEventArgs args)
            {
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
                if (view == ActiveView) address.Text = view.Source.ToString();
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
                WriteRuntimeEvidence(CoreWebView2Environment.GetAvailableBrowserVersionString());
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
            core.ProcessFailed += delegate
            {
                protectionPulse.Active = false;
                runtimeStatus.Text = "Renderer/runtime failure detected - reload this tab";
            };
        }

        private void AttachRequestPolicy(WebView2 view)
        {
            CoreWebView2 core = view.CoreWebView2;
            core.AddWebResourceRequestedFilter(
                "*",
                CoreWebView2WebResourceContext.All,
                CoreWebView2WebResourceRequestSourceKinds.Document
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
            highRiskMode = !highRiskMode;
            highRiskButton.Text = highRiskMode ? "Native guard: Strict" : "Native guard: Standard";
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
                "Protection: Browser Shields MV3 + native High-Risk policy\r\n" +
                "Policy provenance: " + trackerDomains.Count + " reviewed domains, " + trackingParameters.Count + " tracking parameters\r\n" +
                "Tracking prevention: Balanced\r\n" +
                "YouTube UI assist: enabled (best effort)\r\n" +
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
                browserViews.Remove(view);
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
                address.Text = ActiveView.Source.ToString();
            }
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
                "host_filter_source_kinds=document",
                "request_count_coverage=native_policy_only",
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
            foreach (WebView2 view in browserViews.ToArray()) view.Dispose();
            browserViews.Clear();
        }
    }
}
