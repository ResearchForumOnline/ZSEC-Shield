using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace TalkToAI.ZsecBrowserPreview
{
    internal static class BrowserLoginDialogText
    {
        internal static string SingleLineUsername(string value)
        {
            if (String.IsNullOrEmpty(value)) return "(empty username)";
            char[] characters = value.ToCharArray();
            for (int index = 0; index < characters.Length; index++)
            {
                if (Char.IsControl(characters[index])) characters[index] = ' ';
            }
            string display = new String(characters).Trim();
            if (display.Length == 0) return "(empty username)";
            return display.Length <= 160 ? display : display.Substring(0, 159) + "…";
        }

        internal static Label PromptText(string text, int height)
        {
            Label label = BrowserDialogTheme.Description(text);
            label.Width = 500;
            label.Height = height;
            label.AutoEllipsis = true;
            return label;
        }
    }

    internal enum BrowserLoginSaveDecision
    {
        NotNow,
        Save,
        NeverForSite
    }

    internal sealed class BrowserLoginSavePrompt : Form
    {
        internal BrowserLoginSaveDecision Decision { get; private set; }

        internal BrowserLoginSavePrompt(string origin, string username, bool isUpdate)
        {
            Decision = BrowserLoginSaveDecision.NotNow;
            Text = (isUpdate ? "Update password" : "Save password") + " - ZSEC Browser";
            Size = new Size(580, 360);
            MinimumSize = new Size(520, 330);
            BrowserDialogTheme.Apply(this);
            AccessibleName = isUpdate ? "Confirm password update" : "Confirm password save";
            AccessibleDescription = "No password value is displayed in this confirmation.";

            FlowLayoutPanel content = BrowserDialogTheme.PagePanel();
            content.Controls.Add(BrowserLoginDialogText.PromptText(
                isUpdate
                    ? "Update the saved password for this exact HTTPS website and username?"
                    : "Save this password in the encrypted local vault?",
                42
            ));
            Label site = BrowserLoginDialogText.PromptText("Website: " + origin, 56);
            site.AccessibleName = "Login website " + origin;
            string displayedUsername = BrowserLoginDialogText.SingleLineUsername(username);
            Label user = BrowserLoginDialogText.PromptText(
                "Username: " + displayedUsername,
                48
            );
            user.AccessibleName = String.IsNullOrEmpty(username)
                ? "Login username is empty"
                : "Login username " + displayedUsername;
            content.Controls.Add(site);
            content.Controls.Add(user);
            content.Controls.Add(BrowserLoginDialogText.PromptText(
                "The password is not shown here. Never for this site stores only this HTTPS origin in local browser settings; you can clear that list in Settings > Passwords.",
                52
            ));

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Dock = DockStyle.Bottom;
            actions.Height = 58;
            actions.Padding = new Padding(8);
            actions.FlowDirection = FlowDirection.RightToLeft;
            actions.BackColor = BrowserDialogTheme.Background;
            Button save = BrowserDialogTheme.Button(
                isUpdate ? "Update" : "Save",
                isUpdate ? "Confirm password update" : "Confirm password save"
            );
            Button notNow = BrowserDialogTheme.Button("Not now", "Do not save this password now");
            notNow.DialogResult = DialogResult.Cancel;
            Button never = BrowserDialogTheme.Button(
                "Never for this site",
                "Never ask to save passwords for this exact HTTPS site"
            );
            save.Click += delegate { Decide(BrowserLoginSaveDecision.Save); };
            notNow.Click += delegate { Decide(BrowserLoginSaveDecision.NotNow); };
            never.Click += delegate { Decide(BrowserLoginSaveDecision.NeverForSite); };
            actions.Controls.Add(save);
            actions.Controls.Add(notNow);
            actions.Controls.Add(never);

            Controls.Add(content);
            Controls.Add(actions);
            AcceptButton = save;
            CancelButton = notNow;
        }

        private void Decide(BrowserLoginSaveDecision decision)
        {
            Decision = decision;
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    internal sealed class BrowserCredentialPickerDialog : Form
    {
        private readonly IList<BrowserVaultEntry> entries;
        private readonly ListBox usernames;

        internal BrowserVaultEntry SelectedEntry { get; private set; }

        internal BrowserCredentialPickerDialog(string origin, IList<BrowserVaultEntry> candidates)
        {
            if (candidates == null || candidates.Count < 2)
                throw new ArgumentException("At least two credentials are required.", "candidates");
            entries = candidates;
            Text = "Choose login - ZSEC Browser";
            Size = new Size(560, 390);
            MinimumSize = new Size(480, 340);
            BrowserDialogTheme.Apply(this);
            AccessibleName = "Choose a saved login";
            AccessibleDescription = "Choose a username for " + origin + ". Passwords are not shown.";

            Label description = BrowserLoginDialogText.PromptText(
                "Multiple usernames are saved for " + origin +
                    ". Choose which one to fill. ZSEC will not submit the form.",
                56
            );
            description.Dock = DockStyle.Top;
            description.Padding = new Padding(12, 10, 12, 4);
            usernames = new ListBox();
            usernames.Dock = DockStyle.Fill;
            usernames.BackColor = BrowserDialogTheme.Surface;
            usernames.ForeColor = BrowserDialogTheme.Foreground;
            usernames.AccessibleName = "Saved usernames";
            usernames.AccessibleDescription =
                "Saved usernames for this exact HTTPS website. Passwords are not displayed.";
            foreach (BrowserVaultEntry entry in entries)
                usernames.Items.Add(BrowserLoginDialogText.SingleLineUsername(entry.Username));
            usernames.SelectedIndex = 0;
            usernames.DoubleClick += delegate { SelectCredential(); };

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Dock = DockStyle.Bottom;
            actions.Height = 56;
            actions.Padding = new Padding(8);
            actions.FlowDirection = FlowDirection.RightToLeft;
            actions.BackColor = BrowserDialogTheme.Background;
            Button fill = BrowserDialogTheme.Button("Fill", "Fill the selected saved login");
            Button cancel = BrowserDialogTheme.Button("Cancel", "Do not fill a saved login");
            fill.Click += delegate { SelectCredential(); };
            cancel.DialogResult = DialogResult.Cancel;
            actions.Controls.Add(fill);
            actions.Controls.Add(cancel);

            Controls.Add(usernames);
            Controls.Add(description);
            Controls.Add(actions);
            AcceptButton = fill;
            CancelButton = cancel;
        }

        private void SelectCredential()
        {
            if (usernames.SelectedIndex < 0 || usernames.SelectedIndex >= entries.Count) return;
            SelectedEntry = entries[usernames.SelectedIndex];
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
