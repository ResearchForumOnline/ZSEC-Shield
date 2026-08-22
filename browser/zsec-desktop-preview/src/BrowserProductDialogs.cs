using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace TalkToAI.ZsecBrowserPreview
{
    internal static class BrowserDialogTheme
    {
        internal static readonly Color Background = Color.FromArgb(4, 12, 18);
        internal static readonly Color Surface = Color.FromArgb(15, 34, 43);
        internal static readonly Color Foreground = Color.FromArgb(232, 240, 245);
        internal static readonly Color Muted = Color.FromArgb(157, 181, 192);
        internal static readonly Color Accent = Color.FromArgb(0, 229, 170);

        internal static void Apply(Form form)
        {
            form.BackColor = Background;
            form.ForeColor = Foreground;
            form.Font = new Font("Segoe UI", 9F);
            form.StartPosition = FormStartPosition.CenterParent;
            form.ShowIcon = false;
            form.MinimizeBox = false;
        }

        internal static Button Button(string text, string accessibleName)
        {
            Button button = new Button();
            button.Text = text;
            button.AutoSize = true;
            button.MinimumSize = new Size(96, 34);
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = Color.FromArgb(42, 75, 88);
            button.BackColor = Surface;
            button.ForeColor = Foreground;
            button.AccessibleName = accessibleName;
            return button;
        }

        internal static Label Description(string text)
        {
            Label label = new Label();
            label.Text = text;
            label.AutoSize = false;
            label.Width = 680;
            label.Height = 42;
            label.ForeColor = Muted;
            label.Margin = new Padding(4, 4, 4, 8);
            return label;
        }

        internal static FlowLayoutPanel PagePanel()
        {
            FlowLayoutPanel panel = new FlowLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.FlowDirection = FlowDirection.TopDown;
            panel.WrapContents = false;
            panel.AutoScroll = true;
            panel.Padding = new Padding(16);
            panel.BackColor = Background;
            return panel;
        }

        internal static CheckBox CheckBox(string text, string accessibleName)
        {
            CheckBox box = new CheckBox();
            box.Text = text;
            box.AutoSize = false;
            box.Width = 680;
            box.Height = 32;
            box.ForeColor = Foreground;
            box.AccessibleName = accessibleName;
            return box;
        }

        internal static DataGridView Grid()
        {
            DataGridView grid = new DataGridView();
            grid.Dock = DockStyle.Fill;
            grid.ReadOnly = true;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            grid.BackgroundColor = Background;
            grid.GridColor = Color.FromArgb(35, 61, 71);
            grid.BorderStyle = BorderStyle.None;
            grid.RowHeadersVisible = false;
            grid.MultiSelect = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.DefaultCellStyle.BackColor = Surface;
            grid.DefaultCellStyle.ForeColor = Foreground;
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(24, 78, 73);
            grid.DefaultCellStyle.SelectionForeColor = Color.White;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(9, 24, 31);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Foreground;
            grid.EnableHeadersVisualStyles = false;
            return grid;
        }
    }

    internal sealed class BookmarksDialog : Form
    {
        private readonly BrowserDataStore store;
        private readonly BrowserProductData data;
        private readonly Action<string> openUrl;
        private readonly DataGridView grid;

        internal BookmarksDialog(
            BrowserDataStore browserStore,
            BrowserProductData productData,
            Action<string> openBookmark
        )
        {
            store = browserStore;
            data = productData;
            openUrl = openBookmark;
            Text = "Bookmarks - ZSEC Browser";
            Size = new Size(820, 560);
            MinimumSize = new Size(660, 420);
            BrowserDialogTheme.Apply(this);

            grid = BrowserDialogTheme.Grid();
            grid.AccessibleName = "Saved bookmarks";
            grid.Columns.Add("Title", "Name");
            grid.Columns.Add("Url", "Address");
            grid.Columns[0].FillWeight = 35;
            grid.Columns[1].FillWeight = 65;
            grid.CellDoubleClick += delegate { OpenSelected(); };

            FlowLayoutPanel commands = new FlowLayoutPanel();
            commands.Dock = DockStyle.Bottom;
            commands.Height = 52;
            commands.Padding = new Padding(8);
            commands.BackColor = BrowserDialogTheme.Background;
            Button open = BrowserDialogTheme.Button("Open", "Open selected bookmark");
            Button remove = BrowserDialogTheme.Button("Remove", "Remove selected bookmark");
            Button import = BrowserDialogTheme.Button("Import HTML", "Import bookmarks from HTML");
            Button export = BrowserDialogTheme.Button("Export HTML", "Export bookmarks to HTML");
            Button close = BrowserDialogTheme.Button("Close", "Close bookmarks");
            open.Click += delegate { OpenSelected(); };
            remove.Click += delegate { RemoveSelected(); };
            import.Click += delegate { ImportBookmarks(); };
            export.Click += delegate { ExportBookmarks(); };
            close.Click += delegate { Close(); };
            commands.Controls.AddRange(new Control[] { open, remove, import, export, close });

            Controls.Add(grid);
            Controls.Add(commands);
            AcceptButton = open;
            CancelButton = close;
            RefreshRows();
        }

        private string SelectedUrl
        {
            get
            {
                if (grid.SelectedRows.Count != 1) return null;
                return grid.SelectedRows[0].Cells[1].Value as string;
            }
        }

        private void RefreshRows()
        {
            grid.Rows.Clear();
            foreach (BrowserBookmark bookmark in data.Bookmarks)
            {
                grid.Rows.Add(bookmark.Title, bookmark.Url);
            }
        }

        private void OpenSelected()
        {
            string url = SelectedUrl;
            if (String.IsNullOrWhiteSpace(url)) return;
            openUrl(url);
            Close();
        }

        private void RemoveSelected()
        {
            string url = SelectedUrl;
            if (String.IsNullOrWhiteSpace(url)) return;
            try
            {
                store.RemoveBookmark(data, url);
                RefreshRows();
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "The bookmark was not removed.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }

        private void ImportBookmarks()
        {
            OpenFileDialog picker = new OpenFileDialog();
            picker.Filter = "Bookmark HTML (*.html;*.htm)|*.html;*.htm|All files (*.*)|*.*";
            picker.CheckFileExists = true;
            if (picker.ShowDialog(this) != DialogResult.OK) return;
            try
            {
                int added = store.ImportBookmarksHtml(data, picker.FileName);
                RefreshRows();
                MessageBox.Show(
                    added.ToString() + " bookmark(s) imported.",
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
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
                store.ExportBookmarksHtml(data, picker.FileName);
                MessageBox.Show(
                    "Bookmarks exported to:\r\n" + picker.FileName,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
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
    }

    internal sealed class HistoryDialog : Form
    {
        private readonly BrowserDataStore store;
        private readonly BrowserProductData data;
        private readonly Action<string> openUrl;
        private readonly DataGridView grid;

        internal HistoryDialog(
            BrowserDataStore browserStore,
            BrowserProductData productData,
            Action<string> openHistory
        )
        {
            store = browserStore;
            data = productData;
            openUrl = openHistory;
            Text = "History - ZSEC Browser";
            Size = new Size(900, 600);
            MinimumSize = new Size(700, 440);
            BrowserDialogTheme.Apply(this);

            grid = BrowserDialogTheme.Grid();
            grid.AccessibleName = "Browsing history";
            grid.Columns.Add("Visited", "Visited (UTC)");
            grid.Columns.Add("Title", "Page");
            grid.Columns.Add("Url", "Address");
            grid.Columns[0].FillWeight = 22;
            grid.Columns[1].FillWeight = 28;
            grid.Columns[2].FillWeight = 50;
            grid.CellDoubleClick += delegate { OpenSelected(); };

            FlowLayoutPanel commands = new FlowLayoutPanel();
            commands.Dock = DockStyle.Bottom;
            commands.Height = 52;
            commands.Padding = new Padding(8);
            commands.BackColor = BrowserDialogTheme.Background;
            Button open = BrowserDialogTheme.Button("Open", "Open selected history entry");
            Button clear = BrowserDialogTheme.Button("Clear history", "Clear all local browsing history");
            Button close = BrowserDialogTheme.Button("Close", "Close history");
            open.Click += delegate { OpenSelected(); };
            clear.Click += delegate { ClearHistory(); };
            close.Click += delegate { Close(); };
            commands.Controls.AddRange(new Control[] { open, clear, close });

            Controls.Add(grid);
            Controls.Add(commands);
            AcceptButton = open;
            CancelButton = close;
            RefreshRows();
        }

        private void RefreshRows()
        {
            grid.Rows.Clear();
            foreach (BrowserHistoryEntry entry in data.History)
            {
                grid.Rows.Add(entry.VisitedAtUtc, entry.Title, entry.Url);
            }
        }

        private void OpenSelected()
        {
            if (grid.SelectedRows.Count != 1) return;
            string url = grid.SelectedRows[0].Cells[2].Value as string;
            if (String.IsNullOrWhiteSpace(url)) return;
            openUrl(url);
            Close();
        }

        private void ClearHistory()
        {
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
                store.ClearHistory(data);
                RefreshRows();
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "History was not cleared.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }
    }

    internal sealed class SettingsDialog : Form
    {
        private readonly BrowserSettings working;
        private readonly BrowserRuntimeSnapshot runtime;
        private ComboBox startupMode;
        private TextBox customStartup;
        private CheckBox recordHistory;
        private CheckBox clearHistoryOnExit;
        private CheckBox showBookmarksBar;
        private CheckBox minimizeToTray;
        private CheckBox closeToTray;
        private CheckBox askDownloadLocation;
        private TextBox downloadDirectory;
        private CheckBox nativeStrictMode;

        internal bool ClearHistoryRequested { get; private set; }
        internal bool OpenShieldsRequested { get; private set; }

        internal BrowserSettings Result
        {
            get { return working.Copy(); }
        }

        internal SettingsDialog(BrowserSettings settings, BrowserRuntimeSnapshot snapshot)
        {
            working = settings.Copy();
            runtime = snapshot;
            Text = "Settings - ZSEC Browser";
            Size = new Size(820, 640);
            MinimumSize = new Size(700, 520);
            BrowserDialogTheme.Apply(this);

            TabControl categories = new TabControl();
            categories.Dock = DockStyle.Fill;
            categories.AccessibleName = "ZSEC Browser settings categories";
            categories.TabPages.Add(BuildPrivacyPage());
            categories.TabPages.Add(BuildPermissionsPage());
            categories.TabPages.Add(BuildShieldsPage());
            categories.TabPages.Add(BuildStartupPage());
            categories.TabPages.Add(BuildAppearancePage());
            categories.TabPages.Add(BuildDownloadsPage());
            categories.TabPages.Add(BuildDefaultBehaviorPage());

            FlowLayoutPanel footer = new FlowLayoutPanel();
            footer.Dock = DockStyle.Bottom;
            footer.Height = 54;
            footer.FlowDirection = FlowDirection.RightToLeft;
            footer.Padding = new Padding(8);
            footer.BackColor = BrowserDialogTheme.Background;
            Button save = BrowserDialogTheme.Button("Save", "Save ZSEC Browser settings");
            Button cancel = BrowserDialogTheme.Button("Cancel", "Cancel settings changes");
            save.Click += SaveSettings;
            cancel.DialogResult = DialogResult.Cancel;
            footer.Controls.Add(save);
            footer.Controls.Add(cancel);

            Controls.Add(categories);
            Controls.Add(footer);
            AcceptButton = save;
            CancelButton = cancel;
        }

        private TabPage BuildPrivacyPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Browsing history is stored only in this Windows account under the ZSEC Browser product folder. ZSEC does not add cloud history sync or telemetry in this Community build."
            ));
            recordHistory = BrowserDialogTheme.CheckBox(
                "Save local browsing history",
                "Save local browsing history"
            );
            recordHistory.Checked = working.RecordHistory;
            clearHistoryOnExit = BrowserDialogTheme.CheckBox(
                "Clear local history on clean exit",
                "Clear local history on clean exit"
            );
            clearHistoryOnExit.Checked = working.ClearHistoryOnExit;
            Button clear = BrowserDialogTheme.Button("Clear history now", "Clear browsing history now");
            clear.Click += delegate
            {
                ClearHistoryRequested = true;
                clear.Enabled = false;
                clear.Text = "History will be cleared";
            };
            panel.Controls.Add(recordHistory);
            panel.Controls.Add(clearHistoryOnExit);
            panel.Controls.Add(clear);
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Native tracking-parameter cleanup and Microsoft Balanced tracking prevention remain enabled. Clearing history does not delete bookmarks or the WebView2 profile."
            ));
            return Page("Privacy", panel);
        }

        private TabPage BuildPermissionsPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Community permission policy: deny by default. Camera, microphone, location, notifications and other WebView2 permission requests are denied and are not silently remembered."
            ));
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Per-site permission exceptions are not implemented in this release. This page is intentionally read-only so the UI does not imply a capability the shell cannot enforce."
            ));
            return Page("Permissions", panel);
        }

        private TabPage BuildShieldsPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            string health = runtime.ShieldsExtensionLoaded
                ? runtime.DnrProbePassed
                    ? "Shields extension loaded; the local DNR runtime probe passed in this session."
                    : "Shields extension loaded; the separate DNR acceptance probe has not passed in this session."
                : "Shields extension is unavailable.";
            panel.Controls.Add(BrowserDialogTheme.Description(health));
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Tracking prevention requested: " + (runtime.TrackingPrevention ?? "unavailable") +
                ". Runtime update waiting for restart: " + runtime.RuntimeUpdateAvailable.ToString().ToLowerInvariant() + "."
            ));
            nativeStrictMode = BrowserDialogTheme.CheckBox(
                "Use strict native cross-site active-content policy (may break sites)",
                "Use strict native cross-site active-content policy"
            );
            nativeStrictMode.Checked = working.NativeStrictMode;
            Button controls = BrowserDialogTheme.Button("Open Shields controls", "Open ZSEC Shields extension controls");
            controls.Click += delegate
            {
                OpenShieldsRequested = true;
                DialogResult = DialogResult.OK;
                Close();
            };
            panel.Controls.Add(nativeStrictMode);
            panel.Controls.Add(controls);
            panel.Controls.Add(BrowserDialogTheme.Description(
                "The native strict policy and the extension High-Risk mode are separate controls. ZSEC does not claim they are synchronized."
            ));
            return Page("Shields", panel);
        }

        private TabPage BuildStartupPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Choose what opens when ZSEC Browser starts without an explicit web address. Command-line or shortcut URLs still take precedence."
            ));
            startupMode = new ComboBox();
            startupMode.DropDownStyle = ComboBoxStyle.DropDownList;
            startupMode.Width = 360;
            startupMode.AccessibleName = "Startup page choice";
            startupMode.Items.AddRange(new object[] { "ZSEC home", "Private local new tab", "Custom HTTPS page" });
            startupMode.SelectedIndex = working.StartupMode == "new_tab" ? 1 : working.StartupMode == "custom" ? 2 : 0;
            customStartup = new TextBox();
            customStartup.Width = 620;
            customStartup.Text = working.CustomStartupUrl;
            customStartup.AccessibleName = "Custom HTTPS startup address";
            startupMode.SelectedIndexChanged += delegate
            {
                customStartup.Enabled = startupMode.SelectedIndex == 2;
            };
            customStartup.Enabled = startupMode.SelectedIndex == 2;
            panel.Controls.Add(startupMode);
            panel.Controls.Add(customStartup);
            return Page("Startup", panel);
        }

        private TabPage BuildAppearancePage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            showBookmarksBar = BrowserDialogTheme.CheckBox(
                "Show bookmarks bar",
                "Show bookmarks bar"
            );
            showBookmarksBar.Checked = working.ShowBookmarksBar;
            minimizeToTray = BrowserDialogTheme.CheckBox(
                "Minimize the window to the notification area",
                "Minimize ZSEC Browser to the notification area"
            );
            minimizeToTray.Checked = working.MinimizeToTray;
            panel.Controls.Add(showBookmarksBar);
            panel.Controls.Add(minimizeToTray);
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Appearance: the dark Community shell is the only implemented theme. System font scaling is used; a light theme is not claimed in this release."
            ));
            return Page("Appearance", panel);
        }

        private TabPage BuildDownloadsPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Every download still requires an explicit allow decision. ZSEC never opens downloaded files automatically."
            ));
            askDownloadLocation = BrowserDialogTheme.CheckBox(
                "Ask where to save each approved download",
                "Ask where to save each approved download"
            );
            askDownloadLocation.Checked = working.AskDownloadLocation;
            downloadDirectory = new TextBox();
            downloadDirectory.Width = 620;
            downloadDirectory.Text = working.DownloadDirectory;
            downloadDirectory.ReadOnly = true;
            downloadDirectory.AccessibleName = "Default download directory";
            Button browse = BrowserDialogTheme.Button("Choose folder", "Choose default download folder");
            browse.Click += delegate
            {
                FolderBrowserDialog picker = new FolderBrowserDialog();
                picker.Description = "Choose the default ZSEC Browser download folder";
                picker.SelectedPath = Directory.Exists(downloadDirectory.Text)
                    ? downloadDirectory.Text
                    : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (picker.ShowDialog(this) == DialogResult.OK)
                {
                    downloadDirectory.Text = picker.SelectedPath;
                }
            };
            panel.Controls.Add(askDownloadLocation);
            panel.Controls.Add(downloadDirectory);
            panel.Controls.Add(browse);
            return Page("Downloads", panel);
        }

        private TabPage BuildDefaultBehaviorPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            closeToTray = BrowserDialogTheme.CheckBox(
                "Close button hides the browser in the notification area",
                "Close button minimizes ZSEC Browser to the notification area"
            );
            closeToTray.Checked = working.CloseToTray;
            panel.Controls.Add(closeToTray);
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Default-browser registration is not implemented. This unsigned Community WebView2 shell does not change Windows default-browser settings."
            ));
            panel.Controls.Add(BrowserDialogTheme.Description(
                "HTTPS upgrades, certificate-error blocking, separate profile storage, disabled password autofill, disabled host objects and disabled web messaging remain enforced and are not relaxed here."
            ));
            return Page("Default behavior", panel);
        }

        private static TabPage Page(string title, Control content)
        {
            TabPage page = new TabPage(title);
            page.BackColor = BrowserDialogTheme.Background;
            page.ForeColor = BrowserDialogTheme.Foreground;
            page.Controls.Add(content);
            return page;
        }

        private void SaveSettings(object sender, EventArgs args)
        {
            if (startupMode.SelectedIndex == 2)
            {
                Uri parsed;
                if (!BrowserDataStore.TryNormalizeWebUrl(customStartup.Text, out parsed) ||
                    parsed.Scheme != Uri.UriSchemeHttps)
                {
                    MessageBox.Show(
                        "The custom startup page must be a complete HTTPS address.",
                        "ZSEC Browser",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                    customStartup.Focus();
                    return;
                }
                working.CustomStartupUrl = parsed.AbsoluteUri;
            }
            working.StartupMode = startupMode.SelectedIndex == 1
                ? "new_tab"
                : startupMode.SelectedIndex == 2 ? "custom" : "home";
            working.RecordHistory = recordHistory.Checked;
            working.ClearHistoryOnExit = clearHistoryOnExit.Checked;
            working.ShowBookmarksBar = showBookmarksBar.Checked;
            working.MinimizeToTray = minimizeToTray.Checked;
            working.CloseToTray = closeToTray.Checked;
            working.AskDownloadLocation = askDownloadLocation.Checked;
            working.DownloadDirectory = downloadDirectory.Text;
            working.NativeStrictMode = nativeStrictMode.Checked;
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
