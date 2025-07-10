#!/bin/bash

# Script Name: install-docker-snap.sh
# Purpose: Install Docker using Snap on Ubuntu

echo "🚀 Starting Docker installation via Snap..."

# Check if Snap is installed
if ! command -v snap &> /dev/null
then
    echo "❌ Snap is not installed. Installing Snap..."
    sudo apt update
    sudo apt install -y snapd
fi

# Install Docker via Snap
echo "📦 Installing Docker..."
sudo snap install docker

# Add current user to 'docker' group
echo "👤 Adding current user to 'docker' group..."
sudo groupadd docker 2>/dev/null
sudo usermod -aG docker "$USER"

echo "✅ Docker installation complete. You may need to log out and log back in for group changes to take effect."

# Test Docker
echo "🔍 Verifying Docker installation..."
docker --version && echo "👍 Docker is ready!" || echo "⚠️ Docker may require a reboot or re-login to work properly."

