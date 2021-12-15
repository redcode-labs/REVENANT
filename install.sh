#!/bin/bash
sudo curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall 
sudo chmod 755 msfinstall 
sudo ./msfinstall || sudo apt-get install metasploit-framework 
sudo apt-get install hexyl rofi jq lolcat
sudo snap install ngrok