#!/bin/bash

# Script Name: install-docker-deb.sh
# Description: Install Docker CE 24.0.9 using downloaded .deb packages

echo "📦 Installing Docker CE 24.0.9 via .deb packages..."

# Create a working directory
mkdir -p ~/docker-deb-install && cd ~/docker-deb-install

# Download specific version .deb files from Docker official repo
echo "⬇ Downloading .deb files..."

wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/containerd.io_1.6.21-1_amd64.deb
wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-ce-cli_24.0.9-1~ubuntu.20.04~focal_amd64.deb
wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-ce_24.0.9-1~ubuntu.20.04~focal_amd64.deb
wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-buildx-plugin_0.10.4-1~ubuntu.20.04~focal_amd64.deb
wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-compose-plugin_2.21.0-1~ubuntu.20.04~focal_amd64.deb

# Install in the correct order
echo "⚙ Installing Docker..."
sudo apt install -y ./containerd.io_1.6.21-1_amd64.deb
sudo apt install -y ./docker-ce-cli_24.0.9-1~ubuntu.20.04~focal_amd64.deb
sudo apt install -y ./docker-ce_24.0.9-1~ubuntu.20.04~focal_amd64.deb
sudo apt install -y ./docker-buildx-plugin_0.10.4-1~ubuntu.20.04~focal_amd64.deb
sudo apt install -y ./docker-compose-plugin_2.21.0-1~ubuntu.20.04~focal_amd64.deb

# Add current user to docker group
sudo usermod -aG docker $USER

echo "✅ Docker installed successfully!"
echo "🔁 Please log out and log in again to use Docker without 'sudo'."
