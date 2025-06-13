#!/bin/bash

set -e

echo "==> Starting installation of Trivy and Grype..."

# ---- Install Trivy ----
echo "==> Checking Trivy installation..."
if command -v trivy >/dev/null 2>&1; then
    echo "[✔] Trivy is already installed. Version: $(trivy --version | head -n 1)"
else
    echo "[+] Installing Trivy..."
    sudo apt update
    sudo apt install -y wget apt-transport-https gnupg lsb-release curl

    if ! grep -q "trivy" /etc/apt/sources.list.d/trivy.list 2>/dev/null; then
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/trivy.list
    fi

    sudo apt update
    sudo apt install -y trivy

    echo "[✔] Trivy installed successfully. Version: $(trivy --version | head -n 1)"
fi

# ---- Install Grype ----
echo "==> Checking Grype installation..."
if command -v grype >/dev/null 2>&1; then
    echo "[✔] Grype is already installed. Version: $(grype version | head -n 1)"
else
    echo "[+] Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    echo "[✔] Grype installed successfully. Version: $(grype version | head -n 1)"
fi

echo "✅ All tools installed and ready to use."
