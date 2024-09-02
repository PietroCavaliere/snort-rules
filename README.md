# 🛡️ Snort Rules Configuration Script

This project provides a comprehensive Bash script designed to automate the configuration of Snort, a widely used network intrusion detection system (IDS). The script facilitates the installation, configuration, and customization of Snort by allowing users to add and manage custom detection rules easily. This README provides a detailed overview of the project, including installation instructions, usage guidelines, and customization options.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Script Workflow](#script-workflow)
- [Configuration Details](#configuration-details)
- [Custom Rules](#custom-rules)
- [Examples of Custom Rules](#examples-of-custom-rules)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 📝 Overview

The Snort Rules Configuration Script aims to simplify the setup and management of Snort by automating various configuration tasks. Snort is a powerful network intrusion detection and prevention system (IDS/IPS) capable of performing real-time traffic analysis and packet logging on IP networks. This script helps system administrators and security professionals streamline the process of setting up Snort, configuring its rules, and ensuring it operates efficiently within their network environment.

## ✨ Features

### 🔍 Automated Snort Installation Check

The script checks if Snort is installed on the system. If Snort is not found, the script prompts the user to install it. This feature ensures that users do not proceed with incomplete setups that might lead to errors.

### 📂 Snort Configuration File Detection

The script automatically searches for the Snort configuration file (`snort.conf`). If it cannot locate the file, it prompts the user to manually provide the path, ensuring the correct file is used for subsequent configurations.

### 📁 Dynamic Rule Directory Identification

Based on the Snort configuration file, the script dynamically identifies the directory where Snort rules are stored. This step is crucial for adding new rules to the correct location, preventing configuration errors.

### 📝 Custom Rule Creation

A key feature of the script is the ability to create a custom rules file (`customrules.rules`). Users can define specific network traffic detection rules that cater to their security needs, enhancing the flexibility and effectiveness of Snort.

### 🚫 IP Bypass Configuration

The script provides an option to add specific IP addresses that Snort will bypass during its detection process. This feature is useful for excluding trusted IPs from monitoring, reducing false positives and focusing on potential threats.

### 📊 Predefined Detection Rules

Included in the script are several predefined rules for detecting common network threats, such as:
- **DDoS Attacks**: Detection of SYN floods, UDP floods, ICMP floods, and other types of distributed denial-of-service attacks.
- **Port Scanning**: Identification of various port scanning techniques, including SYN scans, FIN scans, XMAS scans, and more.
- **Malware Traffic**: Detection of traffic patterns associated with known malware and exploits, helping to identify compromised systems and prevent data breaches.

### 🖥️ Syslog Integration

The script includes functionality to configure Snort to log alerts to syslog, which is a standard for system message logging in Unix-like operating systems. This integration allows for centralized logging, which is beneficial for monitoring and analysis.

### 🔧 Rsyslog Configuration Update

If the syslog configuration is enabled, the script updates the `rsyslog.conf` file to ensure Snort logs are captured correctly. It restarts the rsyslog and Snort services to apply these changes, ensuring that the system is correctly configured.

## 📦 Requirements

To successfully use this script, the following requirements must be met:

- **Snort**: Snort must be installed on the system. The script checks for its presence and guides the user accordingly if it's not found.
- **Bash Shell**: The script is written in Bash, and therefore, it must be executed in an environment that supports Bash scripting (e.g., Linux, macOS).
- **Root or Sudo Privileges**: The script requires sufficient permissions to modify system files, such as the Snort configuration file and the rsyslog configuration file. Running the script with root or sudo privileges is recommended.
- **Access to Internet**: Depending on the system setup, access to the internet may be required to download Snort or any dependencies that might be missing.

## ⚙️ Installation

To install and set up the Snort Rules Configuration Script, follow these steps:

### Step 1: Clone the Repository

Clone the repository from GitHub to your local machine using the following commands:

    git clone https://github.com/YourUsername/Snort-Rules-Script.git
    cd Snort-Rules-Script

### Step 2: Install Snort

If Snort is not already installed on your system, you can install it using the package manager of your choice. For example, on a Debian-based system, you can use:

    sudo apt-get update
    sudo apt-get install snort

For other systems, refer to the respective package manager or follow the [official Snort installation guide](https://www.snort.org/documents).

### Step 3: Run the Script

Execute the script by running:

    sudo ./snort-rules.sh

Running the script with `sudo` is important to ensure it has the necessary permissions to modify system files and restart services.

## 🚀 Usage

Once the script is executed, it will guide you through the configuration process. Here is an overview of what you can expect:

1. **Snort Installation Check**: The script will first verify if Snort is installed. If not, it will instruct you to install it.
2. **Configuration File Detection**: It will attempt to locate the `snort.conf` file. If it cannot find it automatically, it will prompt you to enter the path manually.
3. **Rule Directory Identification**: The script will find the directory where Snort rules are stored, using the information in the `snort.conf` file.
4. **Custom Rules Setup**: A `customrules.rules` file will be created or updated in the rules directory. You can then add your custom rules.
5. **IP Bypass Configuration**: The script will ask if you want to exclude any IP addresses from being monitored. If so, you will be prompted to enter the IP addresses.
6. **Syslog Configuration**: You will be asked if you want to log Snort alerts to syslog. If you choose to do so, the script will update the Snort and rsyslog configurations accordingly.
7. **Service Restart**: The script will restart Snort and rsyslog services to apply the changes.

## 🔄 Script Workflow

The script follows a structured workflow to ensure all necessary steps are covered. Here's a more detailed breakdown of the workflow:

1. **Check for Snort Installation**: 
    - If Snort is not installed, the script exits and prompts the user to install Snort.
    - If Snort is installed, it proceeds to locate the configuration file.

2. **Locate Snort Configuration File**:
    - Uses the `find` command to search for `snort.conf`.
    - If the file is found, the path is stored; otherwise, the user is prompted to provide the path manually.

3. **Identify Rules Directory**:
    - Reads the `snort.conf` file to find the line defining the `RULE_PATH`.
    - If the `RULE_PATH` is not found, the script exits and provides an error message.

4. **Create Custom Rules File**:
    - Creates a new file `customrules.rules` in the rules directory.
    - If the file already exists, the script appends any new rules.

5. **IP Bypass Configuration**:
    - Prompts the user if they want to add any IPs to bypass.
    - If the user opts to bypass specific IPs, the IPs are added to the `customrules.rules` file with `pass` rules.

6. **Add Predefined Rules**:
    - The script includes predefined rules for various types of attacks. These are appended to the `customrules.rules` file.

7. **Syslog Configuration**:
    - If the user opts for syslog logging, the script checks and modifies the `snort.conf` to include syslog output.
    - Updates the `rsyslog.conf` to ensure Snort logs are captured, and restarts the rsyslog service.

8. **Restart Services**:
    - The script restarts Snort to apply the new configuration.
    - If syslog integration is enabled, rsyslog is also restarted.

9. **Completion**:
    - The script provides a summary of actions performed and exits.

## 🔧 Configuration Details

The script is designed to be user-friendly, guiding you through each step of the configuration process. Here are some of the key configuration options and details:

### Snort Configuration File (`snort.conf`)

The `snort.conf` file is the main configuration file for Snort. It contains various settings that define how Snort operates, such as network variables, rule paths, output configurations, and more. The script attempts to locate this file automatically but can also handle manual input if needed.

### Rule Directory

The rule directory is where Snort stores its detection rules. The script dynamically identifies this directory based on the `RULE_PATH` variable in the `snort.conf` file. This ensures that any new rules are added to the correct location, maintaining Snort's integrity and performance.

### Custom Rules File (`customrules.rules`)

The `customrules.rules` file is created by the script to store user-defined detection rules. This file is located in the Snort rule directory and can be edited manually to add, modify, or remove rules as needed. These custom rules allow users to tailor the detection capabilities of Snort to their specific network environment and security requirements.

### 🛠️ Custom Rules

Custom rules are user-defined instructions that tell Snort how to detect specific network traffic or activities. These rules are written in a specific format and syntax that Snort understands. The script includes several predefined rules, but you can also add your own custom rules to detect traffic patterns unique to your environment.

#### Rule Syntax

Each Snort rule follows a specific syntax:

- **Action**: The action to take when traffic matches the rule (e.g., `alert`, `log`, `pass`).
- **Proto**: The protocol to match (e.g., `tcp`, `udp`, `icmp`).
- **Src_ip**: The source IP address or network.
- **Src_port**: The source port number.
- **Direction**: The direction of traffic (`->` or `<->`).
- **Dest_ip**: The destination IP address or network.
- **Dest_port**: The destination port number.
- **Options**: Additional options to fine-tune the rule (e.g., `msg`, `sid`, `rev`).

Example of a basic Snort rule:

    alert tcp any any -> 192.168.1.0/24 80 (msg:"TCP traffic detected"; sid:1000001; rev:1;)

### 📚 Examples of Custom Rules

Here are a few examples of custom rules that can be added to the `customrules.rules` file:

1. **Detecting a SYN Flood Attack**:

    alert tcp any any -> $HOME_NET 80 (msg:"Possible TCP SYN Flood attack detected"; flags:S; detection_filter:track by_src, count 20, seconds 3; sid:10000001; rev:1;)

2. **Detecting a DDoS HTTP GET Flood**:

    alert tcp any any -> $HOME_NET 80 (msg:"DDoS HTTP GET Flood detected"; content:"GET"; detection_filter:track by_src, count 20, seconds 10; sid:1000004; rev:1;)

3. **Detecting a SQL Injection Attempt**:

    alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt Detected"; content:"UNION SELECT"; nocase; sid:1000101; rev:1;)

4. **Detecting a Buffer Overflow Attempt**:

    alert tcp any any -> $HOME_NET any (msg:"Buffer Overflow Attempt Detected"; content:"|41 41 41 41 41 41 41 41|"; sid:1000104; rev:1;)

### 🛠️ Adding Custom Rules

To add custom rules, edit the `customrules.rules` file in the Snort rules directory. Follow the syntax outlined above and restart Snort to apply the changes.

## 🛠️ Troubleshooting

### Common Issues

1. **Snort Not Installed**: Ensure Snort is installed before running the script. If not installed, the script will prompt you to do so.
   
2. **Configuration File Not Found**: If the script cannot find the `snort.conf` file, you will need to provide the path manually.

3. **Insufficient Permissions**: Run the script with root or sudo privileges to ensure it has the necessary permissions to modify system files.

4. **Service Not Restarting**: If Snort or rsyslog does not restart, check the respective service status for errors.

### Log File Locations

- **Snort Logs**: The location of Snort logs depends on the output configuration in `snort.conf`. If syslog integration is enabled, logs can be found in `/var/log/syslog` or the specified log file.
- **Rsyslog Logs**: If `rsyslog` is used for logging Snort alerts, check `/var/log/syslog` or the configured log destination.

## 📄 License

This project is licensed under the MIT License. You are free to use, modify, and distribute this script, provided that you include the original license. See the [LICENSE](LICENSE) file for more details.
