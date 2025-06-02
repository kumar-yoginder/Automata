# 1. Update your system
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
sudo apt install -y curl gnupg2

# 3. Import Metasploit signing key
curl https://apt.metasploit.com/metasploit-framework.gpg.key | gpg --dearmor | sudo tee /usr/share/keyrings/metasploit.gpg > /dev/null

# 4. Add Metasploit repository
echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" | sudo tee /etc/apt/sources.list.d/metasploit.list

# 5. Update apt again
sudo apt update

# 6. Install Metasploit Framework (includes msfvenom)
sudo apt install -y metasploit-framework
