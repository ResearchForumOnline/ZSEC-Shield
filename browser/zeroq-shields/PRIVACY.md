# ZSEC Browser Shields privacy contract

- Rules and site-pause decisions are evaluated locally.
- The extension stores only protection toggles and the user-paused domain list.
- It does not collect full URLs, page text, searches, cookies, form fields,
  credentials, browsing history, or file contents.
- It has no analytics, advertising, crash-upload, reputation, or account endpoint.
- YouTube cleanup operates in the YouTube page and sends no report.

The broad host permission exists because a network blocker must evaluate
requests across sites. It is not used to read or transmit page content. Future
cloud reputation or diagnostics must ship as separate, disclosed, consented
features and may not silently weaken this contract.
