using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TalkToAI.ZsecBrowserPreview;

internal static class BrowserProductStateTests
{
    private static int assertions;

    private static void Assert(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(message);
    }

    public static int Main()
    {
        string parent = Path.Combine(
            Path.GetTempPath(),
            "zsec-browser-product-state-tests-" + Guid.NewGuid().ToString("N")
        );
        try
        {
            TestDefaultsAndRoundTrip(Path.Combine(parent, "roundtrip"));
            TestBookmarksAndImportExport(Path.Combine(parent, "bookmarks"));
            TestBrowserMigration(Path.Combine(parent, "migration"));
            TestHistoryPolicyAndBounds(Path.Combine(parent, "history"));
            TestAddressSuggestionsAndSearch(Path.Combine(parent, "suggestions"));
            TestNativeRequestPolicy();
            TestPasswordVault(Path.Combine(parent, "password-vault"));
            TestPasswordVaultTamperFailsClosed(Path.Combine(parent, "password-vault-tamper"));
            TestPasswordVaultUiPolicy();
            TestPasswordVaultKeyFailure(Path.Combine(parent, "password-vault-key-failure"));
            TestCredentialWorkflowPolicy(Path.Combine(parent, "credential-workflow"));
            TestCredentialCsvImport(Path.Combine(parent, "credential-import"));
            TestResponsiveToolbarLayout();
            TestLocalAutomationPolicy();
            Console.WriteLine("Browser product state tests passed: " + assertions.ToString());
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.ToString());
            return 1;
        }
        finally
        {
            if (Directory.Exists(parent)) Directory.Delete(parent, true);
        }
    }

    private static void TestLocalAutomationPolicy()
    {
        Assert(BrowserLocalAutomationPolicy.IsSupportedCommand("ping"), "Automation ping missing.");
        Assert(BrowserLocalAutomationPolicy.IsSupportedCommand("get_state"), "Automation state query missing.");
        Assert(!BrowserLocalAutomationPolicy.IsSupportedCommand("cookies"), "Sensitive automation command accepted.");
        Assert(!BrowserLocalAutomationPolicy.IsSupportedCommand("execute_script"), "Script execution command accepted.");
        string normalized;
        Assert(BrowserLocalAutomationPolicy.TryNormalizeUrl("https://example.com/a", out normalized), "HTTPS URL rejected.");
        Assert(normalized == "https://example.com/a", "Automation URL normalization changed unexpectedly.");
        Assert(!BrowserLocalAutomationPolicy.TryNormalizeUrl("file:///c:/secret.txt", out normalized), "File URL accepted.");
        Assert(!BrowserLocalAutomationPolicy.TryNormalizeUrl("https://user:pass@example.com/", out normalized), "Credential-bearing URL accepted.");
        Assert(BrowserLocalAutomationPolicy.FixedTimeTokenEquals("abc", "abc"), "Equal automation tokens rejected.");
        Assert(!BrowserLocalAutomationPolicy.FixedTimeTokenEquals("abc", "abd"), "Unequal automation tokens accepted.");
    }

    private static void TestCredentialCsvImport(string root)
    {
        Directory.CreateDirectory(root);
        string chromium = Path.Combine(root, "chromium.csv");
        File.WriteAllText(
            chromium,
            "name,url,username,password,note\r\n" +
            "Example,https://EXAMPLE.com/login,reporter,secret,primary\r\n" +
            "Duplicate,https://example.com/other,reporter,other,duplicate\r\n" +
            "Unsafe,http://example.net,person,bad,rejected\r\n" +
            "Quoted,https://news.example,editor,\"comma,password\",\"quoted \"\"note\"\"\"\r\n",
            new UTF8Encoding(false)
        );
        BrowserCredentialImportPlan plan = BrowserCredentialImportPolicy.ParseExport(chromium);
        Assert(plan.SourceFormat.Contains("Chrome"), "Chromium export format was not recognized.");
        Assert(plan.DataRows == 4, "Credential import data-row count is wrong.");
        Assert(plan.Candidates.Count == 2, "Credential import candidate count is wrong.");
        Assert(plan.DuplicateRows == 1, "Credential import duplicate was not counted.");
        Assert(plan.InvalidRows == 1, "Credential import insecure row was not counted invalid.");
        Assert(plan.Candidates[0].Url == "https://example.com", "Imported URL was not origin-bound.");
        Assert(plan.Candidates[1].Password == "comma,password", "Quoted CSV password was parsed incorrectly.");
        Assert(BrowserCredentialImportPolicy.SourceMatchesPlan(chromium, plan),
            "Unchanged credential export did not match its preview hash.");

        FakeImportVault vault = new FakeImportVault(true);
        vault.Entries.Add(new BrowserVaultEntry
        {
            Id = "existing", Url = "https://example.com", Username = "reporter",
            Password = "do-not-overwrite", Notes = String.Empty
        });
        BrowserCredentialImportResult result = BrowserCredentialImportPolicy.ImportNoOverwrite(vault, plan);
        Assert(result.Imported == 1 && result.ExistingSkipped == 1, "Exact identity dedupe result is wrong.");
        Assert(vault.Entries.First(entry => entry.Id == "existing").Password == "do-not-overwrite",
            "Import overwrote an existing credential.");

        string firefox = Path.Combine(root, "firefox.csv");
        File.WriteAllText(firefox,
            "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n" +
            "https://mozilla.example/login,user,pw,,,id,1,2,3\n", new UTF8Encoding(false));
        Assert(BrowserCredentialImportPolicy.ParseExport(firefox).Candidates.Count == 1,
            "Firefox password export was not accepted.");

        string chromiumFour = Path.Combine(root, "chromium-four.csv");
        File.WriteAllText(chromiumFour,
            "name,url,username,password\nSite,https://four.example/path,user,pw\n", new UTF8Encoding(false));
        Assert(BrowserCredentialImportPolicy.ParseExport(chromiumFour).Candidates.Count == 1,
            "Four-column Chromium password export was not accepted.");

        File.AppendAllText(chromium, "changed");
        Assert(!BrowserCredentialImportPolicy.SourceMatchesPlan(chromium, plan),
            "Changed credential export still matched its preview hash.");

        string unknown = Path.Combine(root, "unknown.csv");
        File.WriteAllText(unknown, "site,user,secret\nhttps://example.com,u,p\n", new UTF8Encoding(false));
        bool unknownRejected = false;
        try { BrowserCredentialImportPolicy.ParseExport(unknown); }
        catch (InvalidDataException) { unknownRejected = true; }
        Assert(unknownRejected, "Unknown credential CSV headers were accepted.");

        bool lockedRejected = false;
        try { BrowserCredentialImportPolicy.ImportNoOverwrite(new FakeImportVault(false), plan); }
        catch (InvalidOperationException) { lockedRejected = true; }
        Assert(lockedRejected, "Locked vault accepted a credential import.");

        FakeImportVault failing = new FakeImportVault(true) { FailOnSaveNumber = 2 };
        bool failedClosed = false;
        try { BrowserCredentialImportPolicy.ImportNoOverwrite(failing, plan); }
        catch (InvalidOperationException) { failedClosed = true; }
        Assert(failedClosed && failing.Entries.Count == 0, "Failed import did not roll back created records.");
    }

    private static void TestCredentialWorkflowPolicy(string root)
    {
        string normalized = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(
            "https://EXAMPLE.com:443/login?next=one"
        );
        Assert(normalized == "https://example.com", "Secure origin did not normalize.");
        Assert(
            BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin("https://example.com:8443/a") ==
                "https://example.com:8443",
            "Non-default origin port was lost."
        );
        bool insecureRejected = false;
        try { BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin("http://example.com/login"); }
        catch (ArgumentException) { insecureRejected = true; }
        Assert(insecureRejected, "Insecure credential origin was accepted.");

        string request = Guid.NewGuid().ToString("N");
        string json = "{\"schema\":\"zsec.browser.credential-save-candidate.v1\"," +
            "\"request_id\":\"" + request + "\",\"origin\":\"https://example.com/login\"," +
            "\"username\":\"reporter@example.com\",\"password\":\"test-secret\"}";
        BrowserCredentialMessage message = BrowserCredentialMessage.Parse(
            json, new Uri("https://example.com/account")
        );
        Assert(message.Origin == "https://example.com", "Message origin was not normalized.");
        Assert(message.Kind == BrowserCredentialMessageKind.SaveCandidate, "Message kind is wrong.");
        bool spoofRejected = false;
        try { BrowserCredentialMessage.Parse(json, new Uri("https://evil.example/")); }
        catch (InvalidDataException) { spoofRejected = true; }
        Assert(spoofRejected, "Credential message source-origin spoofing was accepted.");
        bool extraRejected = false;
        try
        {
            BrowserCredentialMessage.Parse(
                json.Substring(0, json.Length - 1) + ",\"command\":\"save\"}",
                new Uri("https://example.com/")
            );
        }
        catch (InvalidDataException) { extraRejected = true; }
        Assert(extraRejected, "Unexpected credential-message field was accepted.");
        string fillJson = "{\"schema\":\"zsec.browser.credential-fill-request.v1\"," +
            "\"request_id\":\"" + Guid.NewGuid().ToString("N") +
            "\",\"origin\":\"https://example.com/\"}";
        BrowserCredentialMessage fillMessage = BrowserCredentialMessage.Parse(
            fillJson, new Uri("https://example.com/login")
        );
        Assert(fillMessage.Kind == BrowserCredentialMessageKind.FillRequest, "Fill schema failed.");
        Assert(fillMessage.Password == null, "Fill request unexpectedly carried a password.");
        BrowserCredentialRequestTracker requests = new BrowserCredentialRequestTracker();
        string issuedRequest = requests.Issue();
        Assert(requests.Consume(issuedRequest), "Issued credential request was not accepted.");
        Assert(!requests.Consume(issuedRequest), "Credential request replay was accepted.");

        BrowserSettings settings = BrowserSettings.CreateDefault();
        Assert(!settings.PasswordSaveEnabled, "Password saving must default off.");
        Assert(!settings.PasswordAutofillEnabled, "Password autofill must default off.");
        BrowserCredentialPromptPlan disabled = BrowserCredentialWorkflowPolicy.EvaluateSavePrompt(
            settings, message, new BrowserVaultEntry[0]
        );
        Assert(disabled.Kind == BrowserCredentialPromptKind.None, "Disabled save policy prompted.");
        settings.PasswordSaveEnabled = true;
        BrowserCredentialPromptPlan save = BrowserCredentialWorkflowPolicy.EvaluateSavePrompt(
            settings, message, new BrowserVaultEntry[0]
        );
        Assert(save.Kind == BrowserCredentialPromptKind.Save, "New credential did not request save.");
        BrowserVaultEntry acceptedSave = BrowserCredentialWorkflowPolicy.BuildAcceptedSave(
            message, save, BrowserCredentialPromptDecision.Save, null
        );
        Assert(
            acceptedSave.Url == "https://example.com" && acceptedSave.Password == "test-secret",
            "Accepted save did not produce the exact validated candidate."
        );
        BrowserVaultEntry existing = new BrowserVaultEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            Url = "https://example.com/other-path",
            Username = message.Username,
            Password = "old-secret"
        };
        BrowserCredentialPromptPlan update = BrowserCredentialWorkflowPolicy.EvaluateSavePrompt(
            settings, message, new[] { existing }
        );
        Assert(update.Kind == BrowserCredentialPromptKind.Update, "Changed password did not request update.");
        BrowserVaultEntry acceptedUpdate = BrowserCredentialWorkflowPolicy.BuildAcceptedSave(
            message, update, BrowserCredentialPromptDecision.Update, existing
        );
        Assert(
            acceptedUpdate.Id == existing.Id && acceptedUpdate.Password == "test-secret",
            "Accepted update did not preserve identity and replace only the password."
        );
        bool mismatchedDecisionRejected = false;
        try
        {
            BrowserCredentialWorkflowPolicy.BuildAcceptedSave(
                message, update, BrowserCredentialPromptDecision.Save, existing
            );
        }
        catch (InvalidOperationException) { mismatchedDecisionRejected = true; }
        Assert(mismatchedDecisionRejected, "Mismatched save/update prompt decision was accepted.");
        existing.Password = message.Password;
        BrowserCredentialPromptPlan unchanged = BrowserCredentialWorkflowPolicy.EvaluateSavePrompt(
            settings, message, new[] { existing }
        );
        Assert(unchanged.Kind == BrowserCredentialPromptKind.None, "Unchanged password prompted again.");
        BrowserCredentialWorkflowPolicy.ApplyPromptDecision(
            settings, message.Origin, BrowserCredentialPromptDecision.NeverForSite
        );
        Assert(
            BrowserCredentialWorkflowPolicy.IsNeverSaveOrigin(settings, "https://example.com/path"),
            "Never-save decision did not persist in settings."
        );
        Assert(
            BrowserCredentialWorkflowPolicy.EvaluateSavePrompt(
                settings, message, new BrowserVaultEntry[0]
            ).Kind == BrowserCredentialPromptKind.None,
            "Never-save site still prompted."
        );

        settings.PasswordAutofillEnabled = true;
        BrowserVaultEntry subdomain = new BrowserVaultEntry
        {
            Id = Guid.NewGuid().ToString("N"),
            Url = "https://sub.example.com/",
            Username = "sub",
            Password = "sub-secret"
        };
        IList<BrowserVaultEntry> fill = BrowserCredentialWorkflowPolicy.SelectAutofillEntries(
            settings,
            new Uri("https://example.com/login"),
            true,
            new[] { existing, subdomain }
        );
        Assert(fill.Count == 1 && fill[0].Id == existing.Id, "Autofill was not exact-origin scoped.");
        Assert(
            BrowserCredentialWorkflowPolicy.SelectAutofillEntries(
                settings, new Uri("https://example.com/"), false, new[] { existing }
            ).Count == 0,
            "Autofill was allowed in a child frame."
        );

        BrowserSettings assistantSettings = BrowserSettings.CreateDefault();
        assistantSettings.PasswordSaveEnabled = true;
        assistantSettings.PasswordAutofillEnabled = true;
        int persisted = 0;
        BrowserVaultService assistantVault = new BrowserVaultService(root);
        BrowserLoginAssistant assistant = new BrowserLoginAssistant(
            assistantVault,
            delegate { return assistantSettings; },
            delegate { persisted++; }
        );
        string assistantRequest = Guid.NewGuid().ToString("N");
        string captureScript = assistant.BuildCaptureScript(
            assistantRequest,
            "https://login.example/path"
        );
        Assert(
            captureScript.Contains("zsec.browser.credential-save-candidate.v1") &&
                captureScript.Contains(assistantRequest),
            "Login capture script omitted its strict schema or request ID."
        );
        string assistantJson = "{\"schema\":\"zsec.browser.credential-save-candidate.v1\"," +
            "\"request_id\":\"" + assistantRequest + "\",\"origin\":\"https://login.example\"," +
            "\"username\":\"reporter\",\"password\":\"assistant-test-secret\"}";
        BrowserCredentialMessage assistantMessage = assistant.ParseCapture(
            assistantJson,
            "https://login.example/form",
            "https://login.example/account"
        );
        Assert(assistantMessage != null, "Exact-origin login capture was rejected.");
        Assert(
            assistant.ParseCapture(
                assistantJson,
                "https://login.example/form",
                "https://different.example/account"
            ) == null,
            "Cross-origin login capture was accepted."
        );
        BrowserCredentialPromptPlan assistantPlan = assistant.EvaluateSave(assistantMessage);
        Assert(assistantPlan.Kind == BrowserCredentialPromptKind.Save, "Login save was not planned.");
        BrowserVaultEntry assistantSaved = assistant.Save(
            assistantMessage,
            assistantPlan,
            BrowserCredentialPromptDecision.Save
        );
        Assert(assistantSaved.Id != null, "Confirmed login save did not reach the vault.");
        Assert(
            assistant.CredentialsForOrigin(new Uri("https://login.example/next")).Count == 1,
            "Exact-origin saved login was not selected for autofill."
        );
        Assert(
            assistant.CredentialsForOrigin(new Uri("https://sub.login.example/")).Count == 0,
            "Subdomain received another origin's saved login."
        );
        assistant.NeverForOrigin("https://blocked.example/path");
        Assert(persisted == 1, "Never-for-site did not request settings persistence.");
        assistantVault.Dispose();

        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        data.Settings.PasswordSaveEnabled = true;
        data.Settings.PasswordAutofillEnabled = true;
        data.Settings.PasswordNeverSaveOrigins = new List<string>
        {
            "https://EXAMPLE.com/path", "https://example.com", "http://unsafe.example"
        };
        store.Save(data);
        BrowserProductData loaded = store.Load();
        Assert(loaded.SchemaVersion == 3, "Credential-settings schema version is wrong.");
        Assert(loaded.Settings.PasswordSaveEnabled, "Password-save opt-in did not persist.");
        Assert(loaded.Settings.PasswordAutofillEnabled, "Autofill opt-in did not persist.");
        Assert(
            loaded.Settings.PasswordNeverSaveOrigins.SequenceEqual(new[] { "https://example.com" }),
            "Never-save origins did not normalize and deduplicate."
        );
        BrowserSettings copied = loaded.Settings.Copy();
        copied.PasswordNeverSaveOrigins.Add("https://copy.example");
        Assert(
            loaded.Settings.PasswordNeverSaveOrigins.Count == 1,
            "Settings copy shared the mutable never-save origin list."
        );
    }

    private static void TestPasswordVault(string root)
    {
        BrowserVaultService service = new BrowserVaultService(root);
        BrowserVaultStatus before = service.GetStatus();
        Assert(!before.IsUnlocked, "Password vault must begin locked.");
        service.Unlock();
        BrowserVaultEntry saved = service.Save(new BrowserVaultEntry
        {
            Url = "https://example.com/login",
            Username = "journalist@example.com",
            Password = "test-only-secret-value",
            Notes = "Test fixture only"
        });
        Assert(saved.Id.Length == 32, "Password record ID is invalid.");
        Assert(service.GetStatus().EntryCount == 1, "Password vault count is wrong.");
        Assert(service.Search("journalist").Count == 1, "Password vault search failed.");
        service.Lock();
        bool locked = false;
        try { service.Get(saved.Id); }
        catch (InvalidOperationException) { locked = true; }
        Assert(locked, "Locked password vault exposed a record.");
        service.Unlock();
        BrowserVaultEntry loaded = service.Get(saved.Id);
        Assert(loaded.Password == "test-only-secret-value", "Password vault round trip failed.");
        string vaultRoot = Path.Combine(root, "password-vault");
        string atRest = String.Join("", Directory.GetFiles(
            vaultRoot, "*.json", SearchOption.AllDirectories
        ).Select(path => File.ReadAllText(path, Encoding.UTF8)));
        Assert(!atRest.Contains("test-only-secret-value"), "Password appeared in plaintext at rest.");
        Assert(!atRest.Contains("journalist@example.com"), "Username appeared in plaintext at rest.");
        loaded.Password = "replacement-test-secret";
        BrowserVaultEntry updated = service.Save(loaded);
        Assert(service.Get(updated.Id).Password == "replacement-test-secret", "Password update failed.");
        string generated = service.GeneratePassword(new BrowserPasswordGenerationOptions
        {
            Length = 32,
            IncludeUppercase = true,
            IncludeLowercase = true,
            IncludeDigits = true,
            IncludeSymbols = true
        });
        Assert(generated.Length == 32, "Generated password length is wrong.");
        Assert(generated.Any(Char.IsUpper), "Generated password omitted uppercase.");
        Assert(generated.Any(Char.IsLower), "Generated password omitted lowercase.");
        Assert(generated.Any(Char.IsDigit), "Generated password omitted digits.");
        Assert(generated.Any(character => !Char.IsLetterOrDigit(character)), "Generated password omitted symbols.");
        service.Delete(updated.Id);
        Assert(service.GetStatus().EntryCount == 0, "Password deletion failed.");
        service.Dispose();
    }

    private static void TestPasswordVaultTamperFailsClosed(string root)
    {
        BrowserPasswordVault vault = new BrowserPasswordVault(root);
        vault.Initialize();
        string id = vault.Store("https://example.org/login", "test", "tamper-fixture");
        string path = Path.Combine(root, "password-vault", "records", id + ".json");
        string document = File.ReadAllText(path, Encoding.UTF8);
        int marker = document.IndexOf("\"ciphertext\":\"", StringComparison.Ordinal);
        Assert(marker >= 0, "Password record ciphertext was not found.");
        int value = marker + "\"ciphertext\":\"".Length;
        char replacement = document[value] == 'A' ? 'B' : 'A';
        document = document.Substring(0, value) + replacement + document.Substring(value + 1);
        File.WriteAllText(path, document, new UTF8Encoding(false));
        bool rejected = false;
        try { vault.Retrieve(id); }
        catch (Exception exception)
        {
            rejected = exception is CryptographicException || exception is InvalidDataException;
        }
        Assert(rejected, "Tampered password ciphertext was accepted.");
        vault.Dispose();
    }

    private static void TestPasswordVaultUiPolicy()
    {
        BrowserVaultEntry entry = new BrowserVaultEntry
        {
            Url = "https://news.example/login",
            Username = "Reporter@Example.com",
            Password = "test-only-value",
            Notes = "Investigations desk"
        };
        Assert(BrowserVaultUiPolicy.ValidateEntry(entry) == null, "Valid vault entry was rejected.");
        Assert(BrowserVaultUiPolicy.Matches(entry, "reporter"), "Username search is not case-insensitive.");
        Assert(BrowserVaultUiPolicy.Matches(entry, "investigations"), "Notes search failed.");
        Assert(!BrowserVaultUiPolicy.Matches(entry, "unrelated"), "Search matched unrelated content.");
        entry.Url = "javascript:alert(1)";
        Assert(BrowserVaultUiPolicy.ValidateEntry(entry) != null, "Unsafe vault URL was accepted.");

        BrowserPasswordGenerationOptions invalid =
            BrowserPasswordGenerationOptions.CreateDefault();
        invalid.Length = 8;
        Assert(
            BrowserVaultUiPolicy.ValidateGenerationOptions(invalid) != null,
            "Short generated-password policy was accepted."
        );

        DateTime start = new DateTime(2026, 8, 22, 20, 0, 0, DateTimeKind.Utc);
        BrowserVaultAutoLockController autoLock = new BrowserVaultAutoLockController(5, start);
        Assert(!autoLock.ShouldLock(start.AddMinutes(4)), "Vault locked before idle timeout.");
        Assert(autoLock.ShouldLock(start.AddMinutes(5)), "Vault did not lock at idle timeout.");
        autoLock.Touch(start.AddMinutes(5));
        Assert(!autoLock.ShouldLock(start.AddMinutes(9)), "Vault activity did not reset timeout.");

        TestClipboard clipboard = new TestClipboard();
        BrowserSensitiveClipboardController sensitive =
            new BrowserSensitiveClipboardController(clipboard);
        sensitive.Copy("secret-one");
        Assert(sensitive.HasPendingValue, "Sensitive clipboard state was not tracked.");
        Assert(sensitive.ClearPending(), "Unchanged sensitive clipboard value was not cleared.");
        sensitive.Copy("secret-two");
        clipboard.Value = "new-user-value";
        Assert(!sensitive.ClearPending(), "Changed user clipboard content was incorrectly cleared.");
        Assert(clipboard.Value == "new-user-value", "Changed clipboard content was not preserved.");

        BrowserSecretRevealController reveal = new BrowserSecretRevealController(
            BrowserVaultUiPolicy.RevealSeconds
        );
        reveal.Reveal(start);
        Assert(reveal.IsRevealed, "Password reveal state was not recorded.");
        Assert(
            !reveal.ShouldConceal(start.AddSeconds(BrowserVaultUiPolicy.RevealSeconds - 1)),
            "Password reveal ended before its bounded timeout."
        );
        Assert(
            reveal.ShouldConceal(start.AddSeconds(BrowserVaultUiPolicy.RevealSeconds)),
            "Password reveal did not end at its bounded timeout."
        );
        reveal.Conceal();
        Assert(!reveal.IsRevealed, "Explicit concealment retained reveal state.");
    }

    private sealed class TestClipboard : IBrowserClipboard
    {
        internal string Value { get; set; }

        public void SetSensitiveText(string value) { Value = value; }

        public bool ClearIfUnchanged(string expectedValue)
        {
            if (!String.Equals(Value, expectedValue, StringComparison.Ordinal)) return false;
            Value = null;
            return true;
        }
    }

    private static void TestPasswordVaultKeyFailure(string root)
    {
        BrowserPasswordVault vault = new BrowserPasswordVault(root);
        vault.Initialize();
        vault.Lock();
        string keyPath = Path.Combine(root, "password-vault", "device-key.json");
        string document = File.ReadAllText(keyPath, Encoding.UTF8);
        int marker = document.IndexOf("\"protected_key\":\"", StringComparison.Ordinal);
        Assert(marker >= 0, "Protected DPAPI key was not found.");
        int value = marker + "\"protected_key\":\"".Length;
        char replacement = document[value] == 'A' ? 'B' : 'A';
        File.WriteAllText(
            keyPath,
            document.Substring(0, value) + replacement + document.Substring(value + 1),
            new UTF8Encoding(false)
        );
        bool rejected = false;
        try { vault.Unlock(); }
        catch (Exception exception)
        {
            rejected = exception is CryptographicException || exception is InvalidDataException;
        }
        Assert(rejected, "Changed or wrong-user DPAPI material was accepted.");
        Assert(!vault.IsUnlocked, "Failed DPAPI unlock left the vault unlocked.");
        vault.Dispose();
    }

    private static void TestDefaultsAndRoundTrip(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        Assert(data.SchemaVersion == 3, "Default schema version is wrong.");
        Assert(data.Settings.StartupMode == "home", "Default startup mode is wrong.");
        Assert(data.Settings.RecordHistory, "History should be enabled by default.");
        Assert(data.Settings.MinimizeToTray, "Minimize-to-tray should be available by default.");
        Assert(!data.Settings.CloseToTray, "The close button must default to a clean exit.");
        Assert(data.Settings.AskDownloadLocation, "Download location prompting should default on.");
        Assert(data.Settings.BlockYoutubeAds, "YouTube ad protection should default on.");
        Assert(data.Settings.SearchEngine == "brave", "Brave Search should be the default.");
        Assert(data.Settings.Theme == "soft_dark", "Soft dark should be the default theme.");
        Assert(data.Settings.AccentColor == "teal", "Teal should be the default accent.");

        data.Settings.StartupMode = "custom";
        data.Settings.CustomStartupUrl = "https://example.com/start";
        data.Settings.NativeStrictMode = true;
        data.Settings.Theme = "slate";
        data.Settings.AccentColor = "violet";
        store.Save(data);
        BrowserProductData loaded = store.Load();
        Assert(loaded.Settings.StartupMode == "custom", "Startup mode did not persist.");
        Assert(loaded.Settings.CustomStartupUrl == "https://example.com/start", "Custom startup URL did not normalize.");
        Assert(loaded.Settings.NativeStrictMode, "Native strict mode did not persist.");
        Assert(loaded.Settings.Theme == "slate", "Theme did not persist.");
        Assert(loaded.Settings.AccentColor == "violet", "Accent did not persist.");

        loaded.Settings.CustomStartupUrl = "javascript:alert(1)";
        loaded.Settings.StartupMode = "custom";
        store.Save(loaded);
        BrowserProductData sanitized = store.Load();
        Assert(
            sanitized.Settings.CustomStartupUrl == "https://talktoai.org/zero-browser/",
            "Unsafe startup URL was not replaced."
        );
    }

    private static void TestBookmarksAndImportExport(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        Assert(store.AddBookmark(data, "Example", "https://example.com/one"), "Bookmark was not added.");
        Assert(!store.AddBookmark(data, "Updated", "https://example.com/one"), "Duplicate bookmark was added.");
        Assert(data.Bookmarks.Count == 1, "Duplicate URL should update one bookmark.");
        Assert(data.Bookmarks[0].Title == "Updated", "Duplicate bookmark title was not updated.");
        Assert(!store.AddBookmark(data, "Unsafe", "javascript:alert(1)"), "Unsafe bookmark URL was accepted.");

        Directory.CreateDirectory(root);
        string export = Path.Combine(root, "bookmarks.html");
        store.ExportBookmarksHtml(data, export);
        string exported = File.ReadAllText(export, Encoding.UTF8);
        Assert(exported.Contains("NETSCAPE-Bookmark-file-1"), "Export is not bookmark HTML.");
        Assert(exported.Contains("https://example.com/one"), "Export omitted bookmark URL.");

        string importRoot = Path.Combine(root, "imported");
        Directory.CreateDirectory(importRoot);
        string import = Path.Combine(importRoot, "input.html");
        File.WriteAllText(
            import,
            "<!doctype html><a href=\"https://example.org/a\">Alpha</a>" +
            "<a href='http://example.net/b'>Beta</a>" +
            "<a href=\"javascript:alert(1)\">Unsafe</a>",
            new UTF8Encoding(false)
        );
        BrowserDataStore importedStore = new BrowserDataStore(importRoot);
        BrowserProductData importedData = importedStore.Load();
        int count = importedStore.ImportBookmarksHtml(importedData, import);
        Assert(count == 2, "Bookmark import count is wrong.");
        Assert(importedData.Bookmarks.Count == 2, "Bookmark import did not preserve two safe URLs.");
        Assert(importedData.Bookmarks.All(item => item.Url.StartsWith("http", StringComparison.Ordinal)), "Unsafe import survived.");
        Assert(importedStore.RemoveBookmark(importedData, "https://example.org/a"), "Bookmark removal failed.");
        Assert(importedData.Bookmarks.Count == 1, "Bookmark removal count is wrong.");
    }

    private static void TestHistoryPolicyAndBounds(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        store.AddHistory(data, "Example", "https://example.com/");
        Assert(data.History.Count == 1, "History entry was not recorded.");
        store.AddHistory(data, "Typed example", "https://example.com/", true);
        Assert(data.History.Count == 1, "A repeat visit should consolidate one URL.");
        Assert(data.History[0].TypedCount == 1, "Typed navigation count was not recorded.");
        data.Settings.RecordHistory = false;
        store.AddHistory(data, "Ignored", "https://example.org/");
        Assert(data.History.Count == 1, "Disabled history still recorded an entry.");

        data.Settings.RecordHistory = true;
        data.History.Clear();
        for (int index = 0; index < BrowserDataStore.MaximumHistoryEntries + 7; index++)
        {
            data.History.Add(new BrowserHistoryEntry
            {
                Title = "Entry " + index.ToString(),
                Url = "https://example.com/" + index.ToString(),
                VisitedAtUtc = "2026-08-22T00:00:00Z"
            });
        }
        store.Save(data);
        BrowserProductData bounded = store.Load();
        Assert(
            bounded.History.Count == BrowserDataStore.MaximumHistoryEntries,
            "History bound was not enforced."
        );
        store.ClearHistory(bounded);
        Assert(store.Load().History.Count == 0, "History clear did not persist.");
    }

    private static void TestBrowserMigration(string root)
    {
        Directory.CreateDirectory(root);
        string bookmarks = Path.Combine(root, "Bookmarks");
        File.WriteAllText(bookmarks,
            "{\"roots\":{\"bookmark_bar\":{\"children\":[" +
            "{\"name\":\"Existing\",\"url\":\"https://example.com/\"}," +
            "{\"name\":\"News\",\"url\":\"https://news.example/story\"}," +
            "{\"name\":\"Unsafe\",\"url\":\"javascript:alert(1)\"}]}}}",
            new UTF8Encoding(false));
        BrowserMigrationProfile profile = new BrowserMigrationProfile
        {
            Browser = "Brave", Name = "Default", Root = root, BookmarkPath = bookmarks
        };
        BrowserDataStore store = new BrowserDataStore(Path.Combine(root, "zsec"));
        BrowserProductData data = store.Load();
        store.AddBookmark(data, "Already here", "https://example.com/");
        BrowserMigrationPlan plan = BrowserMigrationPolicy.Preview(profile, data.Bookmarks);
        Assert(plan.Items.Count == 1, "Migration preview did not filter duplicate and unsafe URLs.");
        Assert(plan.DuplicateCount == 1, "Migration preview duplicate count is wrong.");
        Assert(plan.Items[0].Kind == "bookmark" && plan.Items[0].Url == "https://news.example/story",
            "Migration preview did not preserve the safe bookmark.");
        Assert(plan.SessionBoundary.Contains("Bookmark all tabs"), "Chromium session safety boundary is absent.");
        Assert(BrowserMigrationPolicy.ImportBookmarks(store, data, plan) == 1,
            "One-click bookmark migration count is wrong.");
        Assert(data.Bookmarks.Count == 2, "One-click migration did not preserve existing bookmarks.");

        string session = Path.Combine(root, "sessionstore.json");
        File.WriteAllText(session,
            "{\"windows\":[{\"tabs\":[{\"entries\":[{\"title\":\"Mail\",\"url\":\"https://mail.example/inbox\"},{\"url\":\"file:///secret\"}]}]}]}",
            new UTF8Encoding(false));
        BrowserMigrationProfile firefox = new BrowserMigrationProfile
        {
            Browser = "Firefox", Name = "test.default", Root = root, SessionPath = session
        };
        BrowserMigrationPlan sessionPlan = BrowserMigrationPolicy.Preview(firefox, data.Bookmarks);
        Assert(sessionPlan.Items.Count == 1 && sessionPlan.Items[0].Kind == "tab",
            "Firefox URL-only session preview did not filter non-web state.");
        Assert(sessionPlan.SessionBoundary.Contains("authentication tokens"),
            "Firefox session credential boundary is absent.");
    }

    private static void TestAddressSuggestionsAndSearch(string root)
    {
        BrowserDataStore store = new BrowserDataStore(root);
        BrowserProductData data = store.Load();
        store.AddHistory(data, "Ordinary", "https://ordinary.example/path", false);
        store.AddHistory(data, "Typed", "https://www.typed.example/article", true);
        store.AddBookmark(data, "Saved", "https://saved.example/bookmark");
        string[] suggestions = store.GetAddressSuggestions(data, String.Empty, 20).ToArray();
        Assert(suggestions[0] == "https://www.typed.example/article", "Typed URL was not ranked first.");
        Assert(suggestions.Contains("typed.example/article"), "Scheme-free typed URL suggestion is absent.");
        Assert(suggestions.Contains("saved.example/bookmark"), "Bookmark suggestion is absent.");
        Assert(
            store.GetAddressSuggestions(data, "typed", 20).All(value =>
                value.IndexOf("typed", StringComparison.OrdinalIgnoreCase) >= 0),
            "Address suggestion filtering returned an unrelated URL."
        );
        Assert(
            BrowserSearchProviders.BuildSearchUrl("duckduckgo", "free speech") ==
                "https://duckduckgo.com/?q=free%20speech",
            "DuckDuckGo search URL is wrong."
        );
        Assert(
            BrowserSearchProviders.NormalizeKey("not-a-provider") == "brave",
            "Unknown search providers must fail to the reviewed default."
        );
        Assert(BrowserSearchProviders.All.Count() == 7, "Search provider catalogue drifted.");
    }

    private static void TestNativeRequestPolicy()
    {
        const string Youtube = "https://www.youtube.com/watch?v=test";
        Assert(
            BrowserRequestPolicy.IsYoutubeAdRequest(
                Youtube,
                "https://www.youtube.com/pagead/interaction/"
            ),
            "YouTube page-ad endpoint was not classified."
        );
        Assert(
            BrowserRequestPolicy.IsYoutubeAdRequest(
                Youtube,
                "https://static.doubleclick.net/instream/ad_status.js"
            ),
            "YouTube third-party ad endpoint was not classified."
        );
        Assert(
            !BrowserRequestPolicy.IsYoutubeAdRequest(
                Youtube,
                "https://www.youtube.com/youtubei/v1/player"
            ),
            "The normal YouTube player endpoint must not be blocked."
        );
        string[] trackers = { "doubleclick.net", "tracker.example" };
        Assert(
            BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                "https://news.example/article",
                "https://ads.doubleclick.net/pixel.js",
                trackers
            ),
            "Reviewed third-party tracker was not classified."
        );
        Assert(
            !BrowserRequestPolicy.IsReviewedThirdPartyTracker(
                "https://news.example/article",
                "https://cdn.news.example/app.js",
                trackers
            ),
            "Same-site content was incorrectly classified as a tracker."
        );
        Assert(
            !BrowserRequestPolicy.HostMatchesDomain("notdoubleclick.net", "doubleclick.net"),
            "Tracker matching crossed a DNS label boundary."
        );
    }

    private static void TestResponsiveToolbarLayout()
    {
        Assert(
            BrowserToolbarLayout.NativeGuardLabel(false, 1920) == "Native guard: Standard",
            "Wide toolbar guard label was shortened unexpectedly."
        );
        Assert(
            BrowserToolbarLayout.NativeGuardLabel(true, 960) == "Guard: Strict",
            "Compact toolbar guard label did not preserve its mode."
        );
        Assert(
            BrowserToolbarLayout.AddressWidth(1920, 610) == 1310,
            "Wide toolbar did not allocate the remaining width to the address field."
        );
        Assert(
            BrowserToolbarLayout.AddressWidth(960, 850) ==
                BrowserToolbarLayout.CompactMinimumAddressWidth,
            "Compact toolbar address field fell below its usable minimum."
        );
        Assert(
            BrowserToolbarLayout.AddressWidth(1120, 900) ==
                BrowserToolbarLayout.StandardMinimumAddressWidth,
            "Standard toolbar address field fell below its usable minimum."
        );
    }

    private sealed class FakeImportVault : IVaultService
    {
        private readonly bool unlocked;
        private int saves;
        internal readonly List<BrowserVaultEntry> Entries = new List<BrowserVaultEntry>();
        internal int FailOnSaveNumber { get; set; }

        internal FakeImportVault(bool unlockedValue) { unlocked = unlockedValue; }
        public BrowserVaultStatus GetStatus()
        {
            return new BrowserVaultStatus
            {
                IsAvailable = true, IsUnlocked = unlocked, EntryCount = Entries.Count,
                Message = unlocked ? "Unlocked" : "Locked"
            };
        }
        public IList<BrowserVaultEntry> Search(string query)
        { return Entries.Select(entry => entry.Copy()).ToList(); }
        public BrowserVaultEntry Get(string id)
        { return Entries.FirstOrDefault(entry => entry.Id == id); }
        public BrowserVaultEntry Save(BrowserVaultEntry entry)
        {
            saves++;
            if (FailOnSaveNumber > 0 && saves == FailOnSaveNumber)
                throw new InvalidOperationException("Injected import write failure.");
            BrowserVaultEntry saved = entry.Copy();
            saved.Id = Guid.NewGuid().ToString("N");
            Entries.Add(saved);
            return saved.Copy();
        }
        public void Delete(string id) { Entries.RemoveAll(entry => entry.Id == id); }
        public void Unlock() { }
        public void Lock() { }
        public string GeneratePassword(BrowserPasswordGenerationOptions options)
        { return "not-used"; }
    }
}
