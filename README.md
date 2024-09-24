# Recon4bb
This is a repo for automate routin recon basics 
u can use .csv or .txt file im using regax for find domain in plain text this files :

Subdomain Enumeration (using Subfinder, Amass)
Live Domain Resolution (using Httpx)
JavaScript File Discovery (using LinkFinder)
Vulnerability Scanning (using Nuclei)
Directory Brute-Forcing (using Dirsearch)
All results are organized into project-specific folders, making it easier to manage recon results for multiple target domains.

Tools Integrated:

Subfinder
Httpx
Jsfinder
Nuclei
Dirsearch

Install Required Tools:
un the provided installation script install_recon_tools.sh to install all required tools and dependencies.

chmod +x install_recon_tools.sh
./install_recon_tools.sh
Set API Key:
ask You in CLi promp when running script


Running the Script:

python recon_tool.py <path_to_domains_file>
Follow the Menu:
You’ll be prompted with options to choose the recon method you want to run (Subdomain Enumeration, Vulnerability Scan, etc.).
i am trying manage results in a folder
when Script run , in prompt ask you project name 
And make a directory 
im try to logging beter And if there is a problem with the code, it will be saved in the recon.log file
Im try to optimize Thread and timeouts

updating this repo ...
