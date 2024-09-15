#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
echo "Updating package lists and installing dependencies..."
sudo apt update
sudo apt install -y git python3-pip python3-venv build-essential libssl-dev libffi-dev python3-dev

# Install Go (required for some tools like subfinder, shuffledns)
if ! command_exists go; then
    echo "Installing Go..."
    wget https://dl.google.com/go/go1.16.3.linux-amd64.tar.gz
    sudo tar -xvf go1.16.3.linux-amd64.tar.gz
    sudo mv go /usr/local
    echo "export GOROOT=/usr/local/go" >> ~/.bashrc
    echo "export GOPATH=$HOME/go" >> ~/.bashrc
    echo "export PATH=$GOPATH/bin:$GOROOT/bin:$PATH" >> ~/.bashrc
    source ~/.bashrc
else
    echo "Go is already installed."
fi

# Create Python virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "Python virtual environment already exists."
fi

# Install Subfinder
if ! command_exists subfinder; then
    echo "Installing Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
else
    echo "Subfinder is already installed."
fi

# Install Amass
if ! command_exists amass; then
    echo "Installing Amass..."
    sudo apt install -y snapd
    sudo snap install amass
else
    echo "Amass is already installed."
fi

# Install shuffledns
if ! command_exists shuffledns; then
    echo "Installing shuffledns..."
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
else
    echo "shuffledns is already installed."
fi

# Install httpx
if ! command_exists httpx; then
    echo "Installing httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
    echo "httpx is already installed."
fi

# Install LinkFinder
if [ ! -d "LinkFinder" ]; then
    echo "Installing LinkFinder..."
    git clone https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder
    python3 setup.py install
    cd ..
else
    echo "LinkFinder is already installed."
fi

# Install Nuclei
if ! command_exists nuclei; then
    echo "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    nuclei -update-templates
else
    echo "Nuclei is already installed."
fi

# Install Dirsearch
if [ ! -d "dirsearch" ]; then
    echo "Installing Dirsearch..."
    git clone https://github.com/maurosoria/dirsearch.git
else
    echo "Dirsearch is already installed."
fi

# Install wordlists and resolvers for shuffledns
if [ ! -f "resolvers.txt" ]; then
    echo "Downloading resolvers for shuffledns..."
    wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt
fi

if [ ! -f "wordlist.txt" ]; then
    echo "Downloading wordlist for shuffledns..."
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O wordlist.txt
fi

# Final message
echo "All tools have been installed and are ready for use!"
