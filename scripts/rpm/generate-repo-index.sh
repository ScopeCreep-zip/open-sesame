#!/usr/bin/env bash
# generate-repo-index.sh — write HTML directory listing for a Pages-hosted DNF repo.
# Adapted from github.com/sirredbeard/github-pages-rpm-repo
set -euo pipefail

SITE_DIR="${1:?usage: $0 SITE_DIR}"
REPO_DIR="$SITE_DIR/repo"
test -d "$REPO_DIR"

OWNER="${PAGES_OWNER:-ScopeCreep-zip}"
REPO_NAME="${PAGES_REPO:-open-sesame}"
repo_url="https://${OWNER}.github.io/${REPO_NAME}/repo/"
generated_at="$(date -u +'%Y-%m-%d %H:%M UTC')"

: > "$SITE_DIR/.nojekyll"
[[ -f "$REPO_DIR/manifest.txt" ]] || : > "$REPO_DIR/manifest.txt"

{
  cat <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${REPO_NAME} DNF repo</title>
<style>
  body { font-family: system-ui, sans-serif; line-height: 1.45; max-width: 52rem;
         margin: 1.5rem auto; padding: 0 1rem; }
  code { font-family: ui-monospace, monospace; font-size: 0.92em; }
  table { border-collapse: collapse; width: 100%; margin: 0.75rem 0 1.25rem; }
  th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #8884; }
  td.size { text-align: right; font-variant-numeric: tabular-nums; }
  .muted { opacity: 0.8; font-size: 0.92rem; }
</style>
</head>
<body>
<h1>Open Sesame DNF repository</h1>
<p class="muted">Generated ${generated_at}. Base URL: <code>${repo_url}</code></p>
<p>
This tree is a yum/DNF repository hosted on GitHub Pages.
Point a <code>.repo</code> file at the base URL above.
</p>
<h2>Quick links</h2>
<ul>
  <li><a href="manifest.txt"><code>manifest.txt</code></a></li>
  <li><a href="repodata/repomd.xml"><code>repodata/repomd.xml</code></a></li>
  <li><a href="RPM-GPG-KEY"><code>RPM-GPG-KEY</code></a></li>
  <li><a href="../">Site root</a></li>
</ul>
<h2>Packages</h2>
<table>
<thead><tr><th>File</th><th class="size">Size</th></tr></thead>
<tbody>
HTML
  while IFS= read -r -d '' f; do
    base="$(basename "$f")"
    [[ "$base" == "index.html" ]] && continue
    size="$(wc -c < "$f" | tr -d ' ')"
    if command -v numfmt >/dev/null 2>&1; then
      hsize="$(numfmt --to=iec --suffix=B "$size")"
    else
      hsize="${size}B"
    fi
    printf '<tr><td><a href="%s"><code>%s</code></a></td><td class="size">%s</td></tr>\n' \
      "$base" "$base" "$hsize"
  done < <(find "$REPO_DIR" -maxdepth 1 -type f ! -name 'index.html' -print0 | sort -z)
  cat <<'HTML'
</tbody>
</table>
</body>
</html>
HTML
} > "$REPO_DIR/index.html"

echo "Wrote repo index under $SITE_DIR"
