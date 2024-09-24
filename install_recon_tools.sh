#!/bin/bash

# Func to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update  apt
echo "Updating package list..."
sudo apt update

# install Requ tools
required_tools=("subfinder" "httpx" "dirsearch" "nuclei" "jsfinder" "python3" "pip")

for tool in "${required_tools[@]}"; do
    if ! command_exists "$tool"; then
        echo "Installing $tool..."
        if [ "$tool" == "subfinder" ]; then
            go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        elif [ "$tool" == "httpx" ]; then
            go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        elif [ "$tool" == "dirsearch" ]; then
            git clone https://github.com/maurosoria/dirsearch.git
            cd dirsearch || exit
            chmod +x dirsearch.py
            cd .. || exit
        elif [ "$tool" == "nuclei" ]; then
            go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        elif [ "$tool" == "jsfinder" ]; then
            git clone https://github.com/niklasb/jsfinder.git
            cd jsfinder || exit
            pip install -r requirements.txt
            cd .. || exit
        elif [ "$tool" == "pip" ]; then
            sudo apt install python3-pip
        else
            sudo apt install "$tool"
        fi
    else
        echo "$tool is already installed."
    fi
done

echo "All required tools have been installed."
echo "You can now run the reconnaissance tool using the command: python3 recon_tool.py <input_file> .csv or .txt "
