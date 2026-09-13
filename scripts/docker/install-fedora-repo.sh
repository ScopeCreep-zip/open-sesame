#!/usr/bin/env bash
# install-fedora-repo.sh -- install open-sesame from GitHub Pages DNF repo.
# Runs as root inside the fedora container via docker exec.
set -euo pipefail

curl -fsSL https://scopecreep-zip.github.io/open-sesame/RPM-GPG-KEY \
    -o /etc/pki/rpm-gpg/RPM-GPG-KEY-open-sesame

cat > /etc/yum.repos.d/open-sesame.repo << 'EOF'
[open-sesame]
name=Open Sesame RPMs (GitHub Pages)
baseurl=https://scopecreep-zip.github.io/open-sesame/repo/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-open-sesame
EOF

dnf install -y open-sesame
