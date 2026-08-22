using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace TalkToAI.ZsecBrowserPreview
{
    internal sealed class BrowserLoginAssistant
    {
        private readonly IVaultService vault;
        private readonly Func<BrowserSettings> settingsProvider;
        private readonly Action persistSettings;
        private readonly JavaScriptSerializer serializer;

        internal BrowserLoginAssistant(
            IVaultService vaultService,
            Func<BrowserSettings> currentSettings,
            Action persistSettingsCallback
        )
        {
            if (vaultService == null) throw new ArgumentNullException("vaultService");
            if (currentSettings == null) throw new ArgumentNullException("currentSettings");
            if (persistSettingsCallback == null)
                throw new ArgumentNullException("persistSettingsCallback");
            vault = vaultService;
            settingsProvider = currentSettings;
            persistSettings = persistSettingsCallback;
            serializer = new JavaScriptSerializer
            {
                MaxJsonLength = BrowserCredentialWorkflowPolicy.MaximumMessageBytes,
                RecursionLimit = 8
            };
        }

        internal bool Enabled
        {
            get
            {
                BrowserSettings settings = settingsProvider();
                return settings.PasswordSaveEnabled || settings.PasswordAutofillEnabled;
            }
        }

        internal IList<BrowserVaultEntry> CredentialsForOrigin(Uri sourceUri)
        {
            BrowserSettings settings = settingsProvider();
            if (!settings.PasswordAutofillEnabled || sourceUri == null)
                return new List<BrowserVaultEntry>();
            EnsureUnlocked();
            return BrowserCredentialWorkflowPolicy.SelectAutofillEntries(
                settings,
                sourceUri,
                true,
                vault.Search(sourceUri.Host)
            );
        }

        internal BrowserCredentialMessage ParseCapture(
            string rawJson,
            string messageSource,
            string currentPage
        )
        {
            BrowserSettings settings = settingsProvider();
            if (!settings.PasswordSaveEnabled) return null;
            Uri sourceUri;
            Uri currentUri;
            if (!Uri.TryCreate(messageSource, UriKind.Absolute, out sourceUri) ||
                !Uri.TryCreate(currentPage, UriKind.Absolute, out currentUri)) return null;
            string sourceOrigin;
            string currentOrigin;
            try
            {
                sourceOrigin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(sourceUri);
                currentOrigin = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(currentUri);
            }
            catch (ArgumentException) { return null; }
            if (!String.Equals(sourceOrigin, currentOrigin, StringComparison.Ordinal) ||
                BrowserCredentialWorkflowPolicy.IsNeverSaveOrigin(settings, currentOrigin)) return null;
            BrowserCredentialMessage message;
            try { message = BrowserCredentialMessage.Parse(rawJson, sourceUri); }
            catch (InvalidDataException) { return null; }
            if (message.Kind != BrowserCredentialMessageKind.SaveCandidate) return null;
            return message;
        }

        internal BrowserCredentialPromptPlan EvaluateSave(BrowserCredentialMessage message)
        {
            if (message == null) throw new ArgumentNullException("message");
            EnsureUnlocked();
            return BrowserCredentialWorkflowPolicy.EvaluateSavePrompt(
                settingsProvider(),
                message,
                vault.Search(message.Username ?? String.Empty)
            );
        }

        internal BrowserVaultEntry Save(
            BrowserCredentialMessage message,
            BrowserCredentialPromptPlan plan,
            BrowserCredentialPromptDecision decision
        )
        {
            if (message == null) throw new ArgumentNullException("message");
            if (plan == null || plan.Kind == BrowserCredentialPromptKind.None)
                throw new ArgumentException("A save or update plan is required.", "plan");
            BrowserVaultEntry existing = plan.Kind == BrowserCredentialPromptKind.Update
                ? vault.Get(plan.ExistingEntryId)
                : null;
            BrowserVaultEntry entry = BrowserCredentialWorkflowPolicy.BuildAcceptedSave(
                message,
                plan,
                decision,
                existing
            );
            if (entry == null) throw new InvalidOperationException("Save decision was not accepted.");
            return vault.Save(entry);
        }

        internal void NeverForOrigin(string origin)
        {
            BrowserSettings settings = settingsProvider();
            BrowserCredentialWorkflowPolicy.ApplyPromptDecision(
                settings,
                origin,
                BrowserCredentialPromptDecision.NeverForSite
            );
            persistSettings();
        }

        internal string BuildCaptureScript(string requestId, string expectedOrigin)
        {
            string normalized = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(expectedOrigin);
            Guid request;
            if (!Guid.TryParseExact(requestId, "N", out request))
                throw new ArgumentException("A valid request ID is required.", "requestId");
            return "(()=>{'use strict';const r=" + serializer.Serialize(requestId) +
                ",o=" + serializer.Serialize(normalized) +
                ";if(location.origin!==o||window.__zsecLoginCapture)return;" +
                "window.__zsecLoginCapture=true;document.addEventListener('submit',e=>{" +
                "const f=e.target;if(!(f instanceof HTMLFormElement)||f.__zsecLoginResume)return;" +
                "const p=f.querySelector('input[type=password]');if(!p||!p.value)return;" +
                "const u=f.querySelector('input[autocomplete=username],input[type=email],input[name*=user i],input[name*=email i],input[type=text]');" +
                "e.preventDefault();" +
                "chrome.webview.postMessage({schema:'zsec.browser.credential-save-candidate.v1',request_id:r,origin:location.origin,username:u?u.value:'',password:p.value});" +
                "setTimeout(()=>{f.__zsecLoginResume=true;if(f.requestSubmit)f.requestSubmit();else f.submit();},750);" +
                "},true);})();";
        }

        internal string BuildFillScript(BrowserVaultEntry entry, string expectedOrigin)
        {
            if (entry == null) throw new ArgumentNullException("entry");
            string normalized = BrowserCredentialWorkflowPolicy.NormalizeSecureOrigin(expectedOrigin);
            if (!BrowserCredentialWorkflowPolicy.EntryMatchesExactOrigin(entry, normalized))
                throw new InvalidOperationException("Credential origin does not match the page origin.");
            return "(()=>{'use strict';const o=" + serializer.Serialize(normalized) +
                ",u=" + serializer.Serialize(entry.Username ?? String.Empty) +
                ",p=" + serializer.Serialize(entry.Password ?? String.Empty) +
                ";if(location.origin!==o)return false;const pf=document.querySelector('input[type=password]');" +
                "if(!pf)return false;const uf=document.querySelector('input[autocomplete=username],input[type=email],input[name*=user i],input[name*=email i],input[type=text]');" +
                "const set=(x,v)=>{if(!x)return;const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');d.set.call(x,v);x.dispatchEvent(new Event('input',{bubbles:true}));x.dispatchEvent(new Event('change',{bubbles:true}));};" +
                "set(uf,u);set(pf,p);return true;})();";
        }

        private void EnsureUnlocked()
        {
            if (!vault.GetStatus().IsUnlocked) vault.Unlock();
        }

    }
}
