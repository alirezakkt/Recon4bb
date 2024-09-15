#!/bin/bash

# Update package list
sudo apt update

# Install Go
echo "Installing Go..."
sudo apt install golang -y

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Create Go workspace directory if not present
mkdir -p $HOME/go/bin

# Add Go to the PATH
if ! grep -q "export PATH=\$PATH:\$HOME/go/bin" ~/.bashrc; then
    echo "export PATH=\$PATH:\$HOME/go/bin" >> ~/.bashrc
    source ~/.bashrc
fi

# Install Subfinder
echo "Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Amass
echo "Installing Amass..."
go install -v github.com/owasp-amass/amass/v3/...@master

# Install Httpx
echo "Installing Httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install shuffledns
echo "Installing Shuffledns..."
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Install Nuclei
echo "Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Clone Dirsearch repository
echo "Cloning Dirsearch..."
git clone https://github.com/maurosoria/dirsearch.git

# Clone LinkFinder repository
echo "Cloning LinkFinder..."
git clone https://github.com/GerbenJavado/LinkFinder.git
pip3 install -r LinkFinder/requirements.txt

echo "Installation completed. All tools should now be available in your PATH."
