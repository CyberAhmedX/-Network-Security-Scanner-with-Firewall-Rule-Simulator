# 🌐 Network Security Scanner with Firewall Rule Simulator

## Overview

This project is a **real-time network security scanner and traffic control simulator** built using **Python (Flask)**, **Flask-SocketIO**, and **Nmap**. It provides a fully interactive web interface for scanning hosts and managing firewall-like rules visually and intuitively.

With this tool, users can:

- Perform live port scanning using different modes (TCP SYN, UDP, and service version detection).
- Create and manage firewall simulation rules (`allow` or `deny`) by IP and port.
- See how traffic is filtered based on the applied rules — in real time.
- Understand and visualize network-level security concepts through an educational, hands-on interface.

Whether you're learning cybersecurity, working on networking fundamentals, or building internal tools for demonstration purposes, this project gives you a simplified yet powerful sandbox to work with.

---

## 🔧 Installation

### Requirements

- Python 3.11
- `nmap` installed on your system  
  - **Linux**: `sudo apt install nmap`  
  - **macOS**: `brew install nmap`  
  - **Windows**: [Download from nmap.org](https://nmap.org/download.html)
  - VS Code

## Setup
### Install Python Dependencies

`pip install Flask Flask-SocketIO python-nmap`

# 💡 Features
### 🔍 Flexible Scanning:

- TCP SYN scan

- UDP scan

- Service version detection

### 🛡️ Simulated Firewall:

- Add allow or deny rules by IP and port

- Remove rules dynamically

- Visualize rule impact on scan results

### ⚡ Real-Time UI:

- Uses WebSockets for immediate updates

- No need to refresh or re-run manually

### 🌙 Dark UI Theme:

- Aesthetically styled HTML/CSS interface

- Fully responsive and accessible

# 🚀 How to Use
### Run the Flask server:

`python app.py`

### Open your browser and go to:

`http://127.0.0.1:5000`

### On the interface:

- Enter a target IP address or hostname

- Select scan type (TCP, UDP, version)

- Click Start Scan to begin

- Add firewall rules as needed to block or allow specific traffic

- Watch the results update live based on your rules

# 🎯 Use Cases
- Networking & cybersecurity education

- Visual demo for firewall behavior simulation

- Learning WebSockets and real-time interaction with Flask


### This project is intended for educational and personal use only, feel free to modify and extend it as you wish.

# Project Outputs:
![image](https://github.com/user-attachments/assets/835452ad-53fe-4a72-95fb-2d10ef137244)
![image](https://github.com/user-attachments/assets/ed408bd8-2899-46ca-8602-b859de911bfe)
![image](https://github.com/user-attachments/assets/49be1d39-80d7-42fe-aebe-13d4cb53d3bb)
![image](https://github.com/user-attachments/assets/07933a1b-165b-4cea-849f-f09c5c352c77)
![image](https://github.com/user-attachments/assets/79158ad0-aad9-4f6c-84ff-d94dbcddc1f8)
![image](https://github.com/user-attachments/assets/34830946-a0d8-4aa3-b48e-ab47cb8dab94)
![image](https://github.com/user-attachments/assets/2d6fa1e7-99c5-4385-b029-829c15bc797a)








