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
        internal static Color Background = Color.FromArgb(24, 32, 40);
        internal static Color Surface = Color.FromArgb(40, 53, 65);
        internal static Color Foreground = Color.FromArgb(241, 245, 249);
        internal static Color Muted = Color.FromArgb(184, 197, 208);
        internal static Color Accent = Color.FromArgb(57, 220, 190);
        internal static Color Border = Color.FromArgb(91, 110, 126);

        internal static void Configure(BrowserThemePalette palette)
        {
            if (palette == null) throw new ArgumentNullException("palette");
            Background = palette.Background;
            Surface = palette.Surface;
            Foreground = palette.Foreground;
            Muted = palette.Muted;
            Accent = palette.Accent;
            Border = palette.Border;
        }

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
            button.FlatAppearance.BorderColor = Border;
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
            grid.DefaultCellStyle.SelectionBackColor = Accent;
            grid.DefaultCellStyle.SelectionForeColor = Background;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Background;
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Foreground;
            grid.EnableHeadersVisualStyles = false;
            return grid;
        }

        internal static void ApplyTabs(TabControl tabs)
        {
            tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
            tabs.BackColor = Background;
            tabs.ForeColor = Foreground;
            tabs.DrawItem += delegate(object sender, DrawItemEventArgs args)
            {
                bool selected = args.Index == tabs.SelectedIndex;
                Color fill = selected ? Surface : Background;
                using (SolidBrush brush = new SolidBrush(fill))
                {
                    args.Graphics.FillRectangle(brush, args.Bounds);
                }
                TextRenderer.DrawText(
                    args.Graphics,
                    tabs.TabPages[args.Index].Text,
                    tabs.Font,
                    args.Bounds,
                    selected ? Accent : Foreground,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter
                );
            };
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
            Button migrate = BrowserDialogTheme.Button("Migration centre", "Import from an installed browser profile");
            Button export = BrowserDialogTheme.Button("Export HTML", "Export bookmarks to HTML");
            Button close = BrowserDialogTheme.Button("Close", "Close bookmarks");
            open.Click += delegate { OpenSelected(); };
            remove.Click += delegate { RemoveSelected(); };
            import.Click += delegate { ImportBookmarks(); };
            migrate.Click += delegate { OpenMigrationCentre(); };
            export.Click += delegate { ExportBookmarks(); };
            close.Click += delegate { Close(); };
            commands.Controls.AddRange(new Control[] { open, remove, import, migrate, export, close });

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

        private void OpenMigrationCentre()
        {
            using (BrowserMigrationDialog dialog = new BrowserMigrationDialog(store, data, openUrl))
                dialog.ShowDialog(this);
            RefreshRows();
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

    internal sealed class BrowserMigrationDialog : Form
    {
        private readonly BrowserDataStore store;
        private readonly BrowserProductData data;
        private readonly Action<string> openUrl;
        private readonly ComboBox profiles;
        private readonly DataGridView preview;
        private readonly Label status;
        private List<BrowserMigrationProfile> discovered;
        private BrowserMigrationPlan plan;

        internal BrowserMigrationDialog(BrowserDataStore browserStore, BrowserProductData productData, Action<string> opener)
        {
            store = browserStore; data = productData; openUrl = opener;
            Text = "Migration centre - ZSEC Browser";
            Size = new Size(860, 590); MinimumSize = new Size(700, 460);
            BrowserDialogTheme.Apply(this);
            FlowLayoutPanel top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 105, Padding = new Padding(10), BackColor = BrowserDialogTheme.Background };
            profiles = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 280, AccessibleName = "Source browser profile" };
            profiles.SelectedIndexChanged += delegate { Preview(); };
            Button scan = BrowserDialogTheme.Button("Scan profiles", "Discover installed browser profiles");
            Button inspect = BrowserDialogTheme.Button("Preview", "Preview safe migration items");
            scan.Click += delegate { Discover(); }; inspect.Click += delegate { Preview(); };
            status = BrowserDialogTheme.Description("Select a discovered Brave, Chrome, Edge or Firefox profile. Reading is local and read-only.");
            top.Controls.AddRange(new Control[] { profiles, scan, inspect, status });
            preview = BrowserDialogTheme.Grid(); preview.AccessibleName = "Migration preview";
            preview.Columns.Add("Kind", "Kind"); preview.Columns.Add("Title", "Name"); preview.Columns.Add("Url", "Address");
            preview.Columns[0].FillWeight = 12; preview.Columns[1].FillWeight = 30; preview.Columns[2].FillWeight = 58;
            FlowLayoutPanel bottom = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 58, Padding = new Padding(8), BackColor = BrowserDialogTheme.Background };
            Button import = BrowserDialogTheme.Button("Import bookmarks", "Import all previewed bookmarks");
            Button tabs = BrowserDialogTheme.Button("Open safe tabs", "Open previewed URL-only tabs");
            Button passwords = BrowserDialogTheme.Button("Passwords: export CSV", "Explain password migration boundary");
            Button close = BrowserDialogTheme.Button("Close", "Close migration centre");
            import.Click += delegate { Import(); }; tabs.Click += delegate { OpenTabs(); };
            passwords.Click += delegate { MessageBox.Show("For passwords, export a CSV explicitly from Brave, Chrome, Edge or Firefox, then open ZSEC Passwords and choose Import CSV. ZSEC never decrypts another browser's password database. Delete the plaintext export after a verified import.", "Password migration", MessageBoxButtons.OK, MessageBoxIcon.Information); };
            close.Click += delegate { Close(); };
            bottom.Controls.AddRange(new Control[] { import, tabs, passwords, close });
            Controls.Add(preview); Controls.Add(top); Controls.Add(bottom);
            CancelButton = close; Discover();
        }

        private void Discover()
        {
            discovered = BrowserMigrationPolicy.DiscoverInstalledProfiles();
            profiles.Items.Clear(); foreach (BrowserMigrationProfile profile in discovered) profiles.Items.Add(profile.DisplayName);
            if (profiles.Items.Count > 0) profiles.SelectedIndex = 0;
            else status.Text = "No readable supported profiles were found.";
        }

        private void Preview()
        {
            if (profiles.SelectedIndex < 0 || discovered == null) return;
            try
            {
                plan = BrowserMigrationPolicy.Preview(discovered[profiles.SelectedIndex], data.Bookmarks);
                preview.Rows.Clear(); foreach (BrowserMigrationItem item in plan.Items) preview.Rows.Add(item.Kind, item.Title, item.Url);
                status.Text = plan.Items.Count + " safe unique item(s); " + plan.DuplicateCount + " duplicate(s) skipped. " + plan.SessionBoundary;
            }
            catch (Exception exception) { MessageBox.Show("The profile could not be previewed.\r\n\r\n" + exception.Message, "Migration centre", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        }

        private void Import()
        {
            if (plan == null) return;
            int count = BrowserMigrationPolicy.ImportBookmarks(store, data, plan);
            status.Text = count + " bookmark(s) imported; duplicates were left unchanged. " + plan.SessionBoundary;
        }

        private void OpenTabs()
        {
            if (plan == null) return;
            List<BrowserMigrationItem> tabs = plan.Items.Where(item => item.Kind == "tab").Take(50).ToList();
            if (tabs.Count == 0) { MessageBox.Show(plan.SessionBoundary, "Open-tab migration", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
            if (MessageBox.Show("Open " + tabs.Count + " URL-only tab(s)? No cookies, login state, form data or authentication tokens will be copied.", "Open safe tabs", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            foreach (BrowserMigrationItem tab in tabs) openUrl(tab.Url);
            status.Text = tabs.Count + " URL-only tab(s) opened without session credentials.";
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
        private CheckBox blockYoutubeAds;
        private ComboBox searchEngine;
        private CheckBox askToSavePasswords;
        private CheckBox autofillPasswords;
        private ComboBox themeChoice;
        private ComboBox accentChoice;

        internal bool ClearHistoryRequested { get; private set; }
        internal bool OpenShieldsRequested { get; private set; }
        internal bool OpenPasswordsRequested { get; private set; }

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
            BrowserDialogTheme.ApplyTabs(categories);
            categories.TabPages.Add(BuildPrivacyPage());
            categories.TabPages.Add(BuildPermissionsPage());
            categories.TabPages.Add(BuildShieldsPage());
            categories.TabPages.Add(BuildPasswordsPage());
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
                "Default search engine for words entered in the address bar. The selected provider receives the query and network metadata; ZSEC does not proxy searches in this build."
            ));
            searchEngine = new ComboBox();
            searchEngine.DropDownStyle = ComboBoxStyle.DropDownList;
            searchEngine.Width = 360;
            searchEngine.AccessibleName = "Default address bar search engine";
            foreach (BrowserSearchProvider provider in BrowserSearchProviders.All)
            {
                searchEngine.Items.Add(provider);
                if (provider.Key == BrowserSearchProviders.NormalizeKey(working.SearchEngine))
                {
                    searchEngine.SelectedIndex = searchEngine.Items.Count - 1;
                }
            }
            searchEngine.DisplayMember = "Name";
            if (searchEngine.SelectedIndex < 0) searchEngine.SelectedIndex = 0;
            panel.Controls.Add(searchEngine);
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
            blockYoutubeAds = BrowserDialogTheme.CheckBox(
                "Block YouTube advertising with native request and player-data protection",
                "Block YouTube advertising"
            );
            blockYoutubeAds.Checked = working.BlockYoutubeAds;
            Button controls = BrowserDialogTheme.Button("Open Shields controls", "Open ZSEC Shields extension controls");
            controls.Click += delegate
            {
                OpenShieldsRequested = true;
                DialogResult = DialogResult.OK;
                Close();
            };
            Button journalist = BrowserDialogTheme.Button(
                "Apply Journalist high-risk preset",
                "Apply the local journalist high-risk privacy preset"
            );
            journalist.Click += delegate
            {
                nativeStrictMode.Checked = true;
                blockYoutubeAds.Checked = true;
                recordHistory.Checked = false;
                clearHistoryOnExit.Checked = true;
            };
            Button compatibility = BrowserDialogTheme.Button(
                "Restore standard compatibility",
                "Disable strict third-party active-content blocking"
            );
            compatibility.Click += delegate { nativeStrictMode.Checked = false; };
            panel.Controls.Add(nativeStrictMode);
            panel.Controls.Add(blockYoutubeAds);
            panel.Controls.Add(journalist);
            panel.Controls.Add(compatibility);
            panel.Controls.Add(controls);
            panel.Controls.Add(BrowserDialogTheme.Description(
                "The Journalist preset disables new local history, clears existing history on clean exit, enables native strict third-party active-content blocking, and enables YouTube ad protection. Restore standard compatibility disables only the strict native cross-site rule. The native strict policy and the extension High-Risk mode are separate controls."
            ));
            return Page("Shields", panel);
        }

        private TabPage BuildPasswordsPage()
        {
            FlowLayoutPanel panel = BrowserDialogTheme.PagePanel();
            panel.Controls.Add(BrowserDialogTheme.Description(
                "ZSEC Passwords stores website addresses, usernames, passwords and notes in the local encrypted vault for this Windows account. Passwords are never displayed in the manager list."
            ));
            askToSavePasswords = BrowserDialogTheme.CheckBox(
                "Offer to save or update passwords after a login is submitted",
                "Offer to save or update passwords after login submission"
            );
            askToSavePasswords.AccessibleDescription =
                "Shows a confirmation containing the exact HTTPS website and username. The password is not displayed.";
            askToSavePasswords.Checked = working.PasswordSaveEnabled;
            autofillPasswords = BrowserDialogTheme.CheckBox(
                "Automatically fill a saved login on its exact HTTPS website",
                "Automatically fill saved logins only on their exact HTTPS website"
            );
            autofillPasswords.AccessibleDescription =
                "Fills a username and password on a matching top-level HTTPS page. ZSEC does not submit the form.";
            autofillPasswords.Checked = working.PasswordAutofillEnabled;
            panel.Controls.Add(askToSavePasswords);
            panel.Controls.Add(autofillPasswords);
            Button open = BrowserDialogTheme.Button(
                "Save settings and open ZSEC Passwords",
                "Save these settings and open the encrypted password vault"
            );
            open.Click += delegate
            {
                SaveSettings(open, EventArgs.Empty);
                if (DialogResult == DialogResult.OK) OpenPasswordsRequested = true;
            };
            panel.Controls.Add(open);
            int excludedCount = working.PasswordNeverSaveOrigins == null
                ? 0
                : working.PasswordNeverSaveOrigins.Count;
            Label exclusions = BrowserDialogTheme.Description(
                excludedCount == 0
                    ? "Never-save list: no websites excluded."
                    : "Never-save list: " + excludedCount.ToString() +
                        (excludedCount == 1 ? " website excluded." : " websites excluded.")
            );
            exclusions.AccessibleName = "Password never-save list status";
            Button clearExclusions = BrowserDialogTheme.Button(
                "Clear never-save list",
                "Allow password save prompts again for all excluded websites"
            );
            clearExclusions.Enabled = excludedCount > 0;
            clearExclusions.Click += delegate
            {
                DialogResult answer = MessageBox.Show(
                    "Allow password save prompts again for every website on the never-save list? This change takes effect only after you save Settings.",
                    "Clear never-save list",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2
                );
                if (answer != DialogResult.Yes) return;
                working.PasswordNeverSaveOrigins.Clear();
                exclusions.Text = "Never-save list: no websites excluded. Save Settings to apply.";
                clearExclusions.Enabled = false;
            };
            panel.Controls.Add(exclusions);
            panel.Controls.Add(clearExclusions);
            Label credentialBoundary = BrowserDialogTheme.Description(
                "Both options start off and require your opt-in. Passwords are never saved without confirmation, and ZSEC never submits login forms. Save and fill are limited to the current top-level exact HTTPS origin; HTTP pages, frames, internal pages and other origins are excluded."
            );
            credentialBoundary.Height = 64;
            credentialBoundary.AccessibleName = "Password save and fill security boundary";
            panel.Controls.Add(credentialBoundary);
            return Page("Passwords", panel);
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
            panel.Controls.Add(BrowserDialogTheme.Description(
                "Choose a contrast-tested native browser theme and accent. The palette applies to browser chrome, tabs, local new-tab surfaces and ZSEC dialogs after ZSEC Browser restarts. Web pages keep their own colours."
            ));
            themeChoice = new ComboBox();
            themeChoice.DropDownStyle = ComboBoxStyle.DropDownList;
            themeChoice.Width = 360;
            themeChoice.AccessibleName = "Browser colour theme";
            foreach (string key in BrowserThemePalette.ThemeKeys)
            {
                themeChoice.Items.Add(BrowserThemePalette.ThemeDisplayName(key));
            }
            themeChoice.SelectedIndex = Array.IndexOf(
                BrowserThemePalette.ThemeKeys,
                BrowserThemePalette.NormalizeTheme(working.Theme)
            );
            accentChoice = new ComboBox();
            accentChoice.DropDownStyle = ComboBoxStyle.DropDownList;
            accentChoice.Width = 360;
            accentChoice.AccessibleName = "Browser accent colour";
            foreach (string key in BrowserThemePalette.AccentKeys)
            {
                accentChoice.Items.Add(BrowserThemePalette.AccentDisplayName(key));
            }
            accentChoice.SelectedIndex = Array.IndexOf(
                BrowserThemePalette.AccentKeys,
                BrowserThemePalette.NormalizeAccent(working.AccentColor)
            );
            panel.Controls.Add(themeChoice);
            panel.Controls.Add(accentChoice);
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
                "All supplied palettes avoid white startup surfaces and meet the ZSEC dark-shell contrast floor. System font scaling remains enabled."
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
                "ZSEC Browser is registered as an available HTTP, HTTPS, HTM and HTML handler. Windows protects the actual default-app choice; use Set as default browser from the main menu and confirm the associations in Windows Settings."
            ));
            panel.Controls.Add(BrowserDialogTheme.Description(
                "HTTPS upgrades, certificate-error blocking, separate profile storage, disabled WebView2 password storage and disabled host objects remain enforced. Optional ZSEC local-vault save and fill are controlled on the Passwords page."
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
            working.BlockYoutubeAds = blockYoutubeAds.Checked;
            BrowserSearchProvider selectedProvider = searchEngine.SelectedItem as BrowserSearchProvider;
            working.SearchEngine = selectedProvider == null ? "brave" : selectedProvider.Key;
            working.PasswordSaveEnabled = askToSavePasswords.Checked;
            working.PasswordAutofillEnabled = autofillPasswords.Checked;
            working.Theme = BrowserThemePalette.ThemeKeys[Math.Max(0, themeChoice.SelectedIndex)];
            working.AccentColor = BrowserThemePalette.AccentKeys[Math.Max(0, accentChoice.SelectedIndex)];
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
