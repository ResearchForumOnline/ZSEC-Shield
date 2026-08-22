# ZSEC Browser credential save and autofill policy

Credential capture and autofill are opt-in native-browser capabilities. The
default settings are `PasswordSaveEnabled = false` and
`PasswordAutofillEnabled = false`. An installation or schema migration must not
silently enable either feature.

## Origin boundary

Credential workflows accept only absolute HTTPS origins. Normalization lowercases
the scheme and IDN host, removes paths, queries and fragments, removes the default
443 port, and retains non-default ports. Matching is an ordinal comparison of the
complete normalized origin. Consequently:

- `https://example.com/a` and `https://example.com/b` match;
- `https://example.com` and `https://example.com:8443` do not match;
- `https://example.com` and `https://sub.example.com` do not match;
- HTTP, user-info URLs and malformed URLs are rejected.

Autofill is limited to a top-level document and at most 20 entries whose stored
URL has exactly the same normalized origin. Child frames receive no credentials.

## Save decisions

A validated form submission produces a plan, not a write:

- saving disabled, an excluded site, or an unchanged credential produces no
  prompt;
- a new exact-origin and username pair produces a Save plan;
- a changed password for an existing exact-origin and username pair produces an
  Update plan.

Only a matching explicit Save or Update decision can be converted into a vault
entry. `NotNow` returns no entry. `NeverForSite` stores only the normalized HTTPS
origin in browser settings and never stores the submitted username or password.
Prompt plans bind updates to the existing record ID, exact origin and exact
username so a stale or mismatched decision cannot update another credential.

## Native message contract

The policy parser recognizes exactly two schemas:

- `zsec.browser.credential-save-candidate.v1`: `schema`, a GUID `request_id`,
  `origin`, bounded `username`, and bounded non-empty `password`;
- `zsec.browser.credential-fill-request.v1`: `schema`, GUID `request_id`, and
  `origin`. A fill request cannot carry a password or command.

Messages are bounded to 24 KiB, must be JSON objects with exactly the schema's
fields, and are rejected if the declared origin differs from the trusted source
URI supplied by the native WebView event. Unknown schemas and extra fields such as
`command` fail closed. Native integrations issue request IDs through
`BrowserCredentialRequestTracker`; each ID can be consumed once, pending requests
are bounded to 128, and navigation or tab disposal must clear them.

`BrowserCredentialMessage.Parse` must only receive the native event's source URI;
page-provided source strings are not authoritative. Web messaging remains disabled
unless the integration installs a reviewed, per-navigation handler that enforces
this contract and removes it on navigation or tab disposal. No message contents,
passwords or usernames may be logged.

## Persistence contract

The settings are part of `browser-data.json` schema version 3:

- `PasswordSaveEnabled`
- `PasswordAutofillEnabled`
- `PasswordNeverSaveOrigins`

Never-save origins are normalized, sorted, deduplicated, limited to 500, and
invalid/insecure entries are discarded during state normalization. Settings
copies deep-copy the exclusion list so a cancelled settings dialog cannot mutate
live state through a shared collection.
