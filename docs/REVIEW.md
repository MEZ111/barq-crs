# Offline results review

From an installed BARQ checkout, open saved candidate results in a searchable local dashboard:

```bash
python -m barq_crs.dashboard candidates.json --output review.html
```

Open `review.html` in your browser. Search by title, target, engine or ID; filter severity and engine; select a result to inspect evidence summaries, fingerprints and remediation guidance. Existing output files are not overwritten.

This command reviews existing results. It does not contact targets or verify vulnerabilities. No external scripts or fonts are loaded. Treat reports as private: target names and evidence summaries remain in the HTML. Clipboard availability depends on the browser.
