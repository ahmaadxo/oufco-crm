# OUFCO CRM

Clients, suppliers, pump deals and follow-ups for OUFCO for engineering and contracting.

- `index.html` (with `manifest.json` and the icons) is the CRM page people open.
- `api.mjs` is the server part: sign-in, team accounts and saving records.
- `build.mjs` runs on Netlify and puts those files where Netlify expects them.
- Records are stored in this Netlify project's storage (Netlify Blobs, store `oufco-crm`), not in this repository.

Every change committed to this repository publishes a new version on Netlify, which uses
15 of the account's monthly credits, so make changes in batches.

**Forgotten admin password:** in Netlify, add an environment variable `ADMIN_RESET_PASSWORD`
with a new password (8+ characters), publish again (Deploys → Trigger deploy), then sign in with
the first admin's email and that password. Delete the variable afterwards.
