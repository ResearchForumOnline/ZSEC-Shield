# Browser migration safety contract

ZSEC Browser's **Bookmarks > Bookmark manager > Migration centre** discovers
local Brave, Chrome, Edge and Firefox profiles and automatically previews changes before any
write. Bookmark URLs must be HTTP or HTTPS, are normalized, deduplicated against
existing ZSEC bookmarks, bounded in count and read only from regular bounded
files. Existing bookmarks are not overwritten. Firefox direct import currently
requires a readable plain-JSON bookmark backup; compressed `.jsonlz4` backups
and `places.sqlite` are deliberately reported as unavailable rather than parsed
or decrypted.

Passwords are deliberately not one-click database imports. The user explicitly
exports a password CSV in the source browser, opens **ZSEC Passwords > Import
CSV**, reviews the preview, and imports without overwriting an existing exact
site/username identity. ZSEC never decrypts or copies another browser's login
database. The CSV is plaintext and should be deleted after the import is
verified.

Session migration means URLs only. When a readable Firefox plain recovery JSON
is present, the preview can open up to 50 filtered web URLs after confirmation.
It does not carry cookies, authentication tokens, form state, storage, history,
passkeys, extensions or source-profile settings. Chromium session files are not
parsed because safely separating URLs from other opaque session state is not
reliable in this shell. In Brave, Chrome or Edge, use **Bookmark all tabs**, then
run bookmark migration.
