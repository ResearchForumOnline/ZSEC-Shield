using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class WindowsBrowserClipboard : IBrowserClipboard
    {
        public void SetSensitiveText(string value)
        {
            if (String.IsNullOrEmpty(value)) throw new ArgumentException("Clipboard text is empty.");
            Clipboard.SetText(value, TextDataFormat.UnicodeText);
        }

        public bool ClearIfUnchanged(string expectedValue)
        {
            try
            {
                if (!Clipboard.ContainsText(TextDataFormat.UnicodeText)) return false;
                if (!String.Equals(
                    Clipboard.GetText(TextDataFormat.UnicodeText),
                    expectedValue,
                    StringComparison.Ordinal
                )) return false;
                Clipboard.Clear();
                return true;
            }
            catch (ExternalException)
            {
                return false;
            }
        }
    }

    internal sealed class BrowserVaultDialog : Form
    {
        private readonly IVaultService vault;
        private readonly BrowserSensitiveClipboardController clipboard;
        private readonly BrowserVaultAutoLockController autoLock;
        private readonly TextBox search;
        private readonly DataGridView grid;
        private readonly Label status;
        private readonly Button add;
        private readonly Button edit;
        private readonly Button remove;
        private readonly Button copyUser;
        private readonly Button copyPassword;
        private readonly Button importCsv;
        private readonly Button unlock;
        private readonly Button lockButton;
        private readonly Timer autoLockTimer;
        private readonly Timer clipboardTimer;
        private BrowserVaultEntryDialog activeEntryDialog;

        internal BrowserVaultDialog(IVaultService service, IBrowserClipboard clipboardService)
        {
            if (service == null) throw new ArgumentNullException("service");
            if (clipboardService == null) throw new ArgumentNullException("clipboardService");
            vault = service;
            clipboard = new BrowserSensitiveClipboardController(clipboardService);
            autoLock = new BrowserVaultAutoLockController(
                BrowserVaultUiPolicy.DefaultAutoLockMinutes,
                DateTime.UtcNow
            );

            Text = "Passwords - ZSEC Browser";
            Size = new Size(940, 640);
            MinimumSize = new Size(760, 500);
            BrowserDialogTheme.Apply(this);
            AccessibleName = "ZSEC Browser encrypted password vault";
            AccessibleDescription =
                "Search, add, edit, copy or remove passwords stored by the local encrypted vault.";
            KeyPreview = true;

            Panel searchPanel = new Panel();
            searchPanel.Dock = DockStyle.Top;
            searchPanel.Height = 58;
            searchPanel.Padding = new Padding(12, 12, 12, 8);
            searchPanel.BackColor = BrowserDialogTheme.Background;
            search = new TextBox();
            search.Dock = DockStyle.Fill;
            search.AccessibleName = "Search saved passwords";
            search.AccessibleDescription = "Search website addresses, usernames and notes.";
            search.TextChanged += delegate { Touch(); RefreshRows(); };
            Label searchLabel = new Label();
            searchLabel.Text = "Search";
            searchLabel.Dock = DockStyle.Left;
            searchLabel.Width = 64;
            searchLabel.Padding = new Padding(0, 4, 8, 0);
            searchLabel.ForeColor = BrowserDialogTheme.Foreground;
            searchPanel.Controls.Add(search);
            searchPanel.Controls.Add(searchLabel);

            grid = BrowserDialogTheme.Grid();
            grid.AccessibleName = "Saved password entries";
            grid.AccessibleDescription =
                "Passwords are not displayed. Select an entry to edit or copy its fields.";
            grid.Columns.Add("Site", "Website");
            grid.Columns.Add("Username", "Username");
            grid.Columns.Add("Updated", "Updated (UTC)");
            grid.Columns.Add("Id", "Id");
            grid.Columns[0].FillWeight = 42;
            grid.Columns[1].FillWeight = 38;
            grid.Columns[2].FillWeight = 20;
            grid.Columns[3].Visible = false;
            grid.CellDoubleClick += delegate { EditSelected(); };
            grid.SelectionChanged += delegate { Touch(); RefreshActionAvailability(); };

            FlowLayoutPanel commands = new FlowLayoutPanel();
            commands.Dock = DockStyle.Bottom;
            commands.Height = 98;
            commands.Padding = new Padding(8);
            commands.WrapContents = true;
            commands.BackColor = BrowserDialogTheme.Background;
            add = BrowserDialogTheme.Button("Add", "Add a password entry");
            edit = BrowserDialogTheme.Button("Edit", "Edit selected password entry");
            remove = BrowserDialogTheme.Button("Remove", "Remove selected password entry");
            copyUser = BrowserDialogTheme.Button("Copy username", "Copy selected username for 30 seconds");
            copyPassword = BrowserDialogTheme.Button("Copy password", "Copy selected password for 30 seconds");
            importCsv = BrowserDialogTheme.Button("Import CSV", "Import an explicitly selected browser password CSV");
            unlock = BrowserDialogTheme.Button("Unlock", "Unlock the local password vault");
            lockButton = BrowserDialogTheme.Button("Lock", "Lock the local password vault now");
            Button close = BrowserDialogTheme.Button("Close", "Close and lock the password vault");
            add.Click += delegate { AddEntry(); };
            edit.Click += delegate { EditSelected(); };
            remove.Click += delegate { RemoveSelected(); };
            copyUser.Click += delegate { CopySelected(false); };
            copyPassword.Click += delegate { CopySelected(true); };
            importCsv.Click += delegate { ImportCsv(); };
            unlock.Click += delegate { UnlockVault(); };
            lockButton.Click += delegate { LockVault("Vault locked."); };
            close.Click += delegate { Close(); };
            commands.Controls.AddRange(new Control[]
            {
                add, edit, remove, copyUser, copyPassword, importCsv, unlock, lockButton, close
            });

            status = new Label();
            status.Dock = DockStyle.Bottom;
            status.Height = 34;
            status.Padding = new Padding(12, 8, 12, 4);
            status.ForeColor = BrowserDialogTheme.Muted;
            status.AccessibleName = "Password vault status";

            autoLockTimer = new Timer();
            autoLockTimer.Interval = 15000;
            autoLockTimer.Tick += delegate
            {
                BrowserVaultStatus current = SafeStatus();
                if (current.IsUnlocked && autoLock.ShouldLock(DateTime.UtcNow))
                {
                    LockVault("Vault locked after five minutes without activity.");
                }
            };
            clipboardTimer = new Timer();
            clipboardTimer.Interval = BrowserVaultUiPolicy.ClipboardSeconds * 1000;
            clipboardTimer.Tick += delegate { ClearPendingClipboard(); };

            Controls.Add(grid);
            Controls.Add(searchPanel);
            Controls.Add(status);
            Controls.Add(commands);
            AcceptButton = edit;
            CancelButton = close;
            Shown += delegate { UnlockVault(); search.Focus(); };
            FormClosed += delegate
            {
                autoLockTimer.Stop();
                clipboardTimer.Stop();
                ClearPendingClipboard();
                try { vault.Lock(); } catch (Exception) { }
                autoLockTimer.Dispose();
                clipboardTimer.Dispose();
            };
            KeyDown += delegate { Touch(); };
            MouseMove += delegate { Touch(); };
            autoLockTimer.Start();
        }

        private string SelectedId
        {
            get
            {
                if (grid.SelectedRows.Count != 1) return null;
                return grid.SelectedRows[0].Cells[3].Value as string;
            }
        }

        private BrowserVaultStatus SafeStatus()
        {
            try
            {
                return vault.GetStatus() ?? new BrowserVaultStatus
                {
                    IsAvailable = false,
                    Message = "Password-vault status is unavailable."
                };
            }
            catch (Exception exception)
            {
                return new BrowserVaultStatus
                {
                    IsAvailable = false,
                    Message = "Password vault error: " + exception.Message
                };
            }
        }

        private void Touch()
        {
            autoLock.Touch(DateTime.UtcNow);
        }

        private void UnlockVault()
        {
            Touch();
            BrowserVaultStatus current = SafeStatus();
            if (!current.IsAvailable)
            {
                status.Text = current.Message ?? "The encrypted password vault is unavailable.";
                unlock.Enabled = false;
                RefreshRows();
                return;
            }
            try
            {
                vault.Unlock();
                status.Text = "Vault unlocked locally. It locks automatically after five idle minutes.";
            }
            catch (Exception exception)
            {
                status.Text = "Vault did not unlock: " + exception.Message;
            }
            RefreshRows();
        }

        private void LockVault(string message)
        {
            if (activeEntryDialog != null) activeEntryDialog.CloseForLock();
            try { vault.Lock(); } catch (Exception exception) { message = "Lock error: " + exception.Message; }
            ClearPendingClipboard();
            grid.Rows.Clear();
            status.Text = message;
            unlock.Enabled = SafeStatus().IsAvailable;
            RefreshActionAvailability();
        }

        private void RefreshRows()
        {
            grid.Rows.Clear();
            BrowserVaultStatus current = SafeStatus();
            unlock.Enabled = current.IsAvailable && !current.IsUnlocked;
            if (!current.IsAvailable || !current.IsUnlocked)
            {
                if (String.IsNullOrWhiteSpace(status.Text))
                {
                    status.Text = current.Message ?? "Vault is locked.";
                }
                RefreshActionAvailability();
                return;
            }
            try
            {
                IList<BrowserVaultEntry> entries = vault.Search(
                    BrowserVaultUiPolicy.NormalizeSearch(search.Text)
                );
                foreach (BrowserVaultEntry entry in entries)
                {
                    grid.Rows.Add(
                        BrowserVaultUiPolicy.DisplaySite(entry.Url),
                        entry.Username,
                        entry.UpdatedAtUtc,
                        entry.Id
                    );
                }
                status.Text = entries.Count.ToString() +
                    (entries.Count == 1 ? " matching entry." : " matching entries.");
            }
            catch (Exception exception)
            {
                status.Text = "Entries could not be read: " + exception.Message;
            }
            RefreshActionAvailability();
        }

        private void RefreshActionAvailability()
        {
            BrowserVaultStatus current = SafeStatus();
            bool unlocked = current.IsAvailable && current.IsUnlocked;
            bool selected = unlocked && !String.IsNullOrWhiteSpace(SelectedId);
            add.Enabled = unlocked;
            edit.Enabled = selected;
            remove.Enabled = selected;
            copyUser.Enabled = selected;
            copyPassword.Enabled = selected;
            importCsv.Enabled = unlocked;
            lockButton.Enabled = unlocked;
        }

        private void AddEntry()
        {
            if (!RequireUnlocked()) return;
            Touch();
            try
            {
                using (BrowserVaultEntryDialog dialog = new BrowserVaultEntryDialog(
                    vault,
                    null,
                    Touch
                ))
                {
                    activeEntryDialog = dialog;
                    if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    try
                    {
                        vault.Save(dialog.Result);
                        status.Text = "Password entry saved.";
                        RefreshRows();
                    }
                    catch (Exception exception)
                    {
                        ShowError("The password entry was not saved.", exception);
                    }
                }
            }
            finally
            {
                activeEntryDialog = null;
                Touch();
            }
        }

        private void EditSelected()
        {
            if (!RequireUnlocked()) return;
            string id = SelectedId;
            if (String.IsNullOrWhiteSpace(id)) return;
            Touch();
            try
            {
                BrowserVaultEntry entry = vault.Get(id);
                using (BrowserVaultEntryDialog dialog = new BrowserVaultEntryDialog(
                    vault,
                    entry,
                    Touch
                ))
                {
                    activeEntryDialog = dialog;
                    if (dialog.ShowDialog(this) != DialogResult.OK) return;
                    vault.Save(dialog.Result);
                }
                status.Text = "Password entry updated.";
                RefreshRows();
            }
            catch (Exception exception)
            {
                ShowError("The password entry was not updated.", exception);
            }
            finally
            {
                activeEntryDialog = null;
                Touch();
            }
        }

        private void RemoveSelected()
        {
            if (!RequireUnlocked()) return;
            string id = SelectedId;
            if (String.IsNullOrWhiteSpace(id)) return;
            DialogResult answer = MessageBox.Show(
                "Permanently remove the selected password entry?",
                "Remove password entry",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2
            );
            if (answer != DialogResult.Yes) return;
            Touch();
            try
            {
                vault.Delete(id);
                status.Text = "Password entry removed.";
                RefreshRows();
            }
            catch (Exception exception)
            {
                ShowError("The password entry was not removed.", exception);
            }
        }

        private void CopySelected(bool password)
        {
            if (!RequireUnlocked()) return;
            string id = SelectedId;
            if (String.IsNullOrWhiteSpace(id)) return;
            Touch();
            try
            {
                BrowserVaultEntry entry = vault.Get(id);
                string value = password ? entry.Password : entry.Username;
                if (String.IsNullOrEmpty(value))
                {
                    status.Text = password ? "This entry has no password." : "This entry has no username.";
                    return;
                }
                ClearPendingClipboard();
                clipboard.Copy(value);
                clipboardTimer.Start();
                status.Text = (password ? "Password" : "Username") +
                    " copied. It will be cleared after 30 seconds if unchanged.";
            }
            catch (Exception exception)
            {
                ShowError("The selected value was not copied.", exception);
            }
        }

        private void ClearPendingClipboard()
        {
            clipboardTimer.Stop();
            clipboard.ClearPending();
        }

        private void ImportCsv()
        {
            if (!RequireUnlocked()) return;
            using (OpenFileDialog picker = new OpenFileDialog())
            {
                picker.Title = "Choose a browser-exported password CSV";
                picker.Filter = "Browser password CSV (*.csv)|*.csv";
                picker.CheckFileExists = true;
                picker.Multiselect = false;
                if (picker.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    BrowserCredentialImportPlan plan = BrowserCredentialImportPolicy.ParseExport(
                        picker.FileName
                    );
                    string preview = plan.SourceFormat + "\r\n\r\n" +
                        "Rows: " + plan.DataRows.ToString() + "\r\n" +
                        "Ready to import: " + plan.Candidates.Count.ToString() + "\r\n" +
                        "Invalid or insecure rows: " + plan.InvalidRows.ToString() + "\r\n" +
                        "Duplicates inside this file: " + plan.DuplicateRows.ToString() + "\r\n\r\n" +
                        "Existing exact HTTPS origin + username entries will be skipped and never overwritten. " +
                        "Cookies, sessions, passkeys, TOTP secrets and history are not imported. Continue?";
                    if (MessageBox.Show(
                        preview, "Preview password import", MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2
                    ) != DialogResult.Yes) return;
                    BrowserCredentialImportResult result =
                        BrowserCredentialImportPolicy.ImportNoOverwrite(vault, plan);
                    RefreshRows();
                    status.Text = "Imported " + result.Imported.ToString() +
                        " password(s); skipped " + result.ExistingSkipped.ToString() +
                        " existing entr" + (result.ExistingSkipped == 1 ? "y." : "ies.");
                    if (MessageBox.Show(
                        "Import completed. Delete the plaintext CSV export now? This cannot be undone.",
                        "Delete plaintext password export", MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2
                    ) == DialogResult.Yes)
                    {
                        if (!BrowserCredentialImportPolicy.SourceMatchesPlan(picker.FileName, plan))
                            throw new IOException("The selected export changed after preview and was not deleted.");
                        File.Delete(picker.FileName);
                        status.Text += " Plaintext CSV deleted at your request.";
                    }
                }
                catch (Exception exception)
                {
                    ShowError("Passwords were not imported safely.", exception);
                }
            }
        }

        private bool RequireUnlocked()
        {
            BrowserVaultStatus current = SafeStatus();
            if (current.IsAvailable && current.IsUnlocked) return true;
            status.Text = current.IsAvailable ? "Unlock the vault first." : current.Message;
            return false;
        }

        private void ShowError(string message, Exception exception)
        {
            MessageBox.Show(
                message + "\r\n\r\n" + exception.Message,
                "ZSEC Browser",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
            );
        }
    }

    internal sealed class BrowserVaultEntryDialog : Form
    {
        private readonly IVaultService vault;
        private readonly Action activity;
        private readonly BrowserVaultEntry working;
        private readonly TextBox url;
        private readonly TextBox username;
        private readonly TextBox password;
        private readonly TextBox notes;
        private readonly NumericUpDown generatedLength;
        private readonly CheckBox upper;
        private readonly CheckBox lower;
        private readonly CheckBox digits;
        private readonly CheckBox symbols;
        private readonly CheckBox show;
        private readonly Timer revealTimer;
        private readonly BrowserSecretRevealController reveal;

        internal BrowserVaultEntry Result { get { return working.Copy(); } }

        internal BrowserVaultEntryDialog(
            IVaultService service,
            BrowserVaultEntry entry,
            Action activityCallback
        )
        {
            vault = service;
            activity = activityCallback ?? delegate { };
            reveal = new BrowserSecretRevealController(BrowserVaultUiPolicy.RevealSeconds);
            working = entry == null ? new BrowserVaultEntry() : entry.Copy();
            Text = entry == null ? "Add password - ZSEC Browser" : "Edit password - ZSEC Browser";
            Size = new Size(720, 600);
            MinimumSize = new Size(620, 520);
            BrowserDialogTheme.Apply(this);
            AccessibleName = entry == null ? "Add password entry" : "Edit password entry";
            KeyPreview = true;

            TableLayoutPanel form = new TableLayoutPanel();
            form.Dock = DockStyle.Fill;
            form.Padding = new Padding(16);
            form.ColumnCount = 2;
            form.RowCount = 9;
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125));
            form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            url = Field("Website address", working.Url, false);
            username = Field("Username", working.Username, false);
            password = Field("Password", working.Password, true);
            notes = Field("Notes", working.Notes, false);
            notes.Multiline = true;
            notes.Height = 100;
            notes.ScrollBars = ScrollBars.Vertical;
            AddRow(form, 0, "Website", url);
            AddRow(form, 1, "Username", username);
            AddRow(form, 2, "Password", password);

            FlowLayoutPanel passwordControls = new FlowLayoutPanel();
            passwordControls.AutoSize = true;
            show = new CheckBox();
            show.Text = "Show password";
            show.AutoSize = true;
            show.AccessibleName = "Show password characters";
            show.CheckedChanged += delegate
            {
                password.UseSystemPasswordChar = !show.Checked;
                if (show.Checked)
                {
                    reveal.Reveal(DateTime.UtcNow);
                    revealTimer.Start();
                }
                else
                {
                    reveal.Conceal();
                    revealTimer.Stop();
                }
                activity();
            };
            revealTimer = new Timer();
            revealTimer.Interval = 1000;
            revealTimer.Tick += delegate
            {
                if (reveal.ShouldConceal(DateTime.UtcNow)) ConcealPassword();
            };
            generatedLength = new NumericUpDown();
            generatedLength.Minimum = BrowserVaultUiPolicy.MinimumGeneratedPasswordLength;
            generatedLength.Maximum = BrowserVaultUiPolicy.MaximumGeneratedPasswordLength;
            generatedLength.Value = 24;
            generatedLength.Width = 64;
            generatedLength.AccessibleName = "Generated password length";
            upper = Option("A-Z", true, "Include uppercase letters");
            lower = Option("a-z", true, "Include lowercase letters");
            digits = Option("0-9", true, "Include digits");
            symbols = Option("Symbols", true, "Include symbols");
            Button generate = BrowserDialogTheme.Button("Generate", "Generate a strong password");
            generate.Click += delegate { GeneratePassword(); };
            passwordControls.Controls.AddRange(new Control[]
            {
                show, generatedLength, upper, lower, digits, symbols, generate
            });
            AddRow(form, 3, "Generator", passwordControls);
            AddRow(form, 4, "Notes", notes);

            Label guidance = BrowserDialogTheme.Description(
                "Passwords stay concealed in the list. Reveal automatically ends after 15 seconds. Copy actions clear unchanged clipboard content after 30 seconds. The vault locks automatically after five idle minutes."
            );
            guidance.AccessibleName = "Password vault safety guidance";
            form.Controls.Add(guidance, 0, 5);
            form.SetColumnSpan(guidance, 2);

            FlowLayoutPanel footer = new FlowLayoutPanel();
            footer.Dock = DockStyle.Bottom;
            footer.Height = 54;
            footer.FlowDirection = FlowDirection.RightToLeft;
            footer.Padding = new Padding(8);
            footer.BackColor = BrowserDialogTheme.Background;
            Button save = BrowserDialogTheme.Button("Save", "Save password entry");
            Button cancel = BrowserDialogTheme.Button("Cancel", "Cancel password changes");
            save.Click += delegate { Save(); };
            cancel.DialogResult = DialogResult.Cancel;
            footer.Controls.Add(save);
            footer.Controls.Add(cancel);

            Controls.Add(form);
            Controls.Add(footer);
            AcceptButton = save;
            CancelButton = cancel;
            Deactivate += delegate { ConcealPassword(); };
            FormClosed += delegate { revealTimer.Stop(); revealTimer.Dispose(); };
            KeyDown += delegate { activity(); };
            MouseMove += delegate { activity(); };
            foreach (TextBox field in new[] { url, username, password, notes })
            {
                field.TextChanged += delegate { activity(); };
            }
        }

        internal void CloseForLock()
        {
            ConcealPassword();
            password.Text = String.Empty;
            working.Password = null;
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private void ConcealPassword()
        {
            reveal.Conceal();
            revealTimer.Stop();
            if (show.Checked) show.Checked = false;
            password.UseSystemPasswordChar = true;
        }

        private static TextBox Field(string accessibleName, string value, bool secret)
        {
            TextBox field = new TextBox();
            field.Dock = DockStyle.Top;
            field.Text = value ?? String.Empty;
            field.AccessibleName = accessibleName;
            field.UseSystemPasswordChar = secret;
            return field;
        }

        private static CheckBox Option(string text, bool value, string accessibleName)
        {
            CheckBox option = new CheckBox();
            option.Text = text;
            option.Checked = value;
            option.AutoSize = true;
            option.AccessibleName = accessibleName;
            return option;
        }

        private static void AddRow(TableLayoutPanel form, int row, string labelText, Control field)
        {
            Label label = new Label();
            label.Text = labelText;
            label.AutoSize = true;
            label.ForeColor = BrowserDialogTheme.Foreground;
            label.Padding = new Padding(0, 7, 0, 0);
            form.Controls.Add(label, 0, row);
            form.Controls.Add(field, 1, row);
        }

        private void GeneratePassword()
        {
            if (!String.IsNullOrEmpty(password.Text))
            {
                DialogResult replace = MessageBox.Show(
                    "Replace the password currently in this field with a newly generated password?",
                    "Replace password",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2
                );
                if (replace != DialogResult.Yes) return;
            }
            BrowserPasswordGenerationOptions options = new BrowserPasswordGenerationOptions
            {
                Length = Decimal.ToInt32(generatedLength.Value),
                IncludeUppercase = upper.Checked,
                IncludeLowercase = lower.Checked,
                IncludeDigits = digits.Checked,
                IncludeSymbols = symbols.Checked
            };
            string error = BrowserVaultUiPolicy.ValidateGenerationOptions(options);
            if (error != null)
            {
                MessageBox.Show(error, "ZSEC Browser", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                password.Text = vault.GeneratePassword(options);
                password.Focus();
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    "A password was not generated.\r\n\r\n" + exception.Message,
                    "ZSEC Browser",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }

        private void Save()
        {
            working.Url = url.Text.Trim();
            working.Username = username.Text;
            working.Password = password.Text;
            working.Notes = notes.Text;
            string error = BrowserVaultUiPolicy.ValidateEntry(working);
            if (error != null)
            {
                MessageBox.Show(error, "ZSEC Browser", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
