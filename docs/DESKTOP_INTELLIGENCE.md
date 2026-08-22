# ZSEC desktop threat-intelligence updater

The desktop intelligence subsystem builds a deterministic, reviewable advisory
catalog from authoritative public sources. It is intentionally separate from the
signed scanner-rule feed described in [FEED_FORMAT.md](FEED_FORMAT.md).

An advisory says that a vulnerability or security update may matter to a desktop.
It is not proof that a device is vulnerable, a file is malicious, or a detection
rule is correct. The updater therefore never converts advisory text into scanner
signatures.

## Safety contract

Every accepted catalog contains this policy object, and the validator rejects any
different value:

```json
{
  "auto_remediation_allowed": false,
  "data_only": true,
  "detection_rules_derived": false,
  "malware_samples_allowed": false,
  "remote_commands_allowed": false
}
```

The updater:

- performs credential-free HTTPS GET requests only to exact allowlisted URLs;
- follows at most three redirects and only while the result remains on the same
  source allowlist;
- caps every response at 16 MiB and the normalized catalog at 8 MiB;
- rejects duplicate JSON keys, invalid Unicode, XML document type/entity
  declarations, missing required fields, invalid dates, duplicate record IDs,
  unknown product references, malformed URLs, and schema extensions;
- stores only advisory metadata and source digests—never malware, exploit code,
  attachments, binaries, scripts, or vendor page JavaScript;
- does not execute catalog content, change firewall or operating-system settings,
  install packages, apply patches, quarantine files, or remove another security
  product;
- creates no scanner rule and makes no primary-antivirus or real-time-protection
  claim.

## Authoritative sources

| Source ID | Authority and endpoint | Accepted use |
| --- | --- | --- |
| `cisa-kev` | [CISA Known Exploited Vulnerabilities JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Desktop-relevant KEV records. CISA exploitation status is retained as sourced evidence. |
| `microsoft-msrc` | [Microsoft MSRC CVRF v3 API](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json) | The latest monthly document, filtered by explicit Windows 10/11, Edge, Defender, Office, and desktop .NET product IDs. |
| `ubuntu-usn` | [Ubuntu Security Notices RSS](https://ubuntu.com/security/notices/rss.xml) | Current notices with explicit desktop, browser, kernel, graphics, printing, Bluetooth, or core operating-system context. |
| `apple-security` | [Apple security releases](https://support.apple.com/en-us/100100) | Reviewable macOS, Safari, Xcode, and GarageBand rows that include an official Apple advisory link. |

The Apple source is HTML because Apple does not publish this table as a documented
JSON API. Its parser accepts only three-cell rows with a parseable release date and
an HTTPS `support.apple.com` article URL. If Apple changes that structure, the run
fails closed instead of guessing.

Ubuntu labels the historical `atom.xml` link but redirects it to `rss.xml`; the
updater uses the final official RSS URL directly.

### Why ClamAV signatures are not downloaded here

ClamAV databases are detection content, not advisory metadata. ClamAV's official
documentation says to update them with `freshclam`, and the CVD format supplies a
signed container. It also warns that bytecode signatures behave like executable
plugins and that unsigned bytecode is not run by default. For those reasons this
generic advisory process does not download, unpack, transform, mirror, or load
ClamAV databases. A future ClamAV provider must call a pinned, supported
`freshclam` installation inside a separately reviewed engine boundary and verify
engine/database compatibility; it must not copy database bytes into this catalog.

See [ClamAV signature management](https://docs.clamav.net/manual/Usage/SignatureManagement.html)
and [ClamAV signature formats and CVD signing](https://docs.clamav.net/manual/Signatures.html).

## Determinism and provenance

For a fixed set of source bytes, the normalized catalog bytes are identical:

- objects are serialized with sorted keys and stable UTF-8 formatting;
- sources are sorted by source ID;
- source contributions are sorted by stable advisory ID;
- the catalog timestamp is the newest authoritative source version, not the local
  wall-clock fetch time;
- each raw source body has a SHA-256 digest;
- each source has a SHA-256 digest of its normalized advisory contribution;
- each source also has a semantic SHA-256 that deliberately excludes raw-body
  digest and ZBA commitment churn while retaining every normalized advisory field,
  source record ID, and parser identity;
- each advisory binds the source-body digest, source record ID, parser version,
  fields, and typed ZBA observation record into a domain-separated SHA-256
  commitment.

ZBA is used only as typed lifecycle/provenance state: the record is in the
`observed` phase with `authoritative-advisory` evidence. It is not encryption, a
cipher, a signature, a malware detector, a CVE scoring method, or proof of device
applicability. Established HTTPS, SHA-256, strict parsing, atomic filesystem writes,
and the existing OS protections provide the actual technical boundaries.

The machine-readable catalog contract is in
[`specs/desktop-intelligence.schema.json`](../specs/desktop-intelligence.schema.json).
The Python validator is stricter in several cross-field areas, including source
counts, digests, allowlists, timestamps, contribution hashes, and ZBA commitments.

## Safe operation

Run an online validation without writing the catalog, state, cache, or backups:

```powershell
python scripts/update_desktop_intelligence.py --dry-run --json
```

Install or refresh the local catalog after review:

```powershell
python scripts/update_desktop_intelligence.py --json
```

Validate from previously checked cache entries without network access:

```powershell
python scripts/update_desktop_intelligence.py --offline --dry-run --json
```

Select one or more sources for diagnostic dry-runs:

```powershell
python scripts/update_desktop_intelligence.py --source cisa-kev --dry-run --json
python scripts/update_desktop_intelligence.py --source microsoft-msrc --source apple-security --dry-run --json
```

Do not install a source subset over a catalog that previously contained more
sources. Source removal is a rollback event and is rejected.

## Cache, atomic writes, backups, and rollback

The HTTP cache stores the exact body plus metadata containing the URL, source ID,
ETag, Last-Modified value, and SHA-256. The next online run sends conditional
headers where a source provides them. A partial cache, changed URL, or digest
mismatch fails closed. `--dry-run` never changes the cache.

Catalog installation uses a cross-platform update lock and atomic replacements.
Before an existing valid catalog changes, its catalog and state files are copied
to a content-addressed backup directory named by the old catalog SHA-256. A backup
is never silently overwritten with different bytes.

Rollback state binds the exact installed catalog bytes and each source's version
and normalized semantic digest. Raw-body and full-contribution digests remain in
the catalog for provenance and integrity, but harmless vendor serialization changes
do not masquerade as new advisory meaning. The updater rejects:

- a source version older than the installed maximum;
- the same source version with different normalized advisory meaning;
- removal of a previously installed source;
- a catalog/state pair that is missing one half, malformed, or digest-inconsistent.

Vendor corrections that change content without advancing a source's authoritative
version require operator review rather than an automatic bypass. There is no
command-line override that weakens this rule.

## Scheduling contract

An operating-system scheduler or Codex automation may run the script once per day,
but the schedule must keep this separation:

1. run `--dry-run --json` and require exit code `0`;
2. review source health, advisory count, and safety-policy fields;
3. run the write operation only inside the repository or an explicitly configured
   state directory;
4. run the repository test suite;
5. report changes for review—do not publish, deploy, commit, create a detection
   signature, apply a patch, or remove an existing antivirus merely because the
   advisory catalog changed.

The script returns exit `2` for every fail-closed source, parsing, schema, cache,
or rollback error.

## Current limitations

- Advisory matching is product-family filtering, not installed-version or CPE
  applicability analysis.
- The Microsoft adapter processes the latest monthly CVRF document. Earlier
  out-of-band revisions remain represented by CISA when exploited, but a separate
  revision-window adapter would be required for complete historical MSRC change
  tracking.
- Apple rows contain release-level metadata. The linked advisory is not recursively
  scraped for CVEs because that would multiply parser and trust surface.
- Ubuntu's RSS feed is a current-window source, not the complete OVAL corpus.
- No source supplies safe general-purpose malware file hashes suitable for direct
  promotion into the signed scanner-rule feed.
- A successful catalog update proves source ingestion and validation only. It does
  not prove endpoint protection efficacy or authorize replacing Malwarebytes,
  Microsoft Defender, XProtect, or another installed control.
