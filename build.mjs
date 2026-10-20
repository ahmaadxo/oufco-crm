// Runs on Netlify before publishing: arranges the CRM's files into the folders Netlify expects.
// Works whether the files were uploaded flat (all at the top level) or already in folders.
import fs from 'node:fs';

const page = ['index.html', 'manifest.json', 'icon-192.png', 'icon-512.png', 'apple-touch-icon.png'];
fs.mkdirSync('public', { recursive: true });
fs.mkdirSync('netlify/functions', { recursive: true });
for (const f of page) if (fs.existsSync(f)) fs.copyFileSync(f, `public/${f}`);
if (fs.existsSync('api.mjs')) fs.copyFileSync('api.mjs', 'netlify/functions/api.mjs');

const missing = [...page.map(f => `public/${f}`), 'netlify/functions/api.mjs'].filter(f => !fs.existsSync(f));
if (missing.length) {
  console.error('\nOUFCO CRM: these files are missing from the GitHub repository:');
  for (const f of missing) console.error('  - ' + f.replace(/^(public|netlify\/functions)\//, ''));
  console.error('Upload all 10 files from the CRM package to the top level of the repository, then deploy again.\n');
  process.exit(1);
}
console.log('OUFCO CRM: files arranged for publishing.');
