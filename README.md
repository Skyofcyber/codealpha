🕵️‍♂️ Network Packet Sniffer using Scapy
🚀 A simple yet powerful network packet sniffer using Python and Scapy

📌 About
This script captures and analyzes network packets in real time, providing valuable insights into network traffic. It helps understand how data flows across a network and can be used for network monitoring, debugging, and security analysis.

🛠 Features
✅ Lists all available network interfaces on a Windows system.
✅ Captures live network packets.
✅ Extracts Source IP, Destination IP, and Protocol type (TCP, UDP, ICMP).
✅ Displays real-time network traffic in a readable format.

⚙️ Installation
1️⃣ Install Python (Ensure Python 3.x is installed on your system)
2️⃣ Install Scapy (If not already installed)
pip install scapy
3️⃣ Run the script
python sniffer.py
📡 How It Works
The script retrieves available network interfaces.
It defines a packet processing function that:
Extracts source & destination IPs
Identifies the protocol (TCP, UDP, ICMP, etc.)
Displays packet details in a readable format
The script captures live packets on a specified network interface using sniff().
🖥 Usage
🔍 Find Your Network Interface
Before running the sniffer, check available network interfaces:
from scapy.arch.windows import get_windows_if_list
print([iface['name'] for iface in get_windows_if_list()])
Replace "Wi-Fi" in the script with the correct interface name:
sniff(iface="Wi-Fi", prn=packet_callback, store=False)
🏃 Running the Sniffer
Run the script with administrator privileges:
python sniffer.py
⚠️ Important Notes
⚡ Running this script requires admin/root privileges.
🔄 The interface name must be correctly set to capture packets.
🛑 Only use this on networks you have permission to monitor.

⚖️ Disclaimer
🚨 This tool is for educational and security research purposes only.
❌ Unauthorized use on networks without proper consent is illegal.

🎯 Future Enhancements
🔹 Add packet filtering options (e.g., capture only TCP or UDP packets).
🔹 Save packet data to a file for further analysis.
🔹 Implement a GUI version for better visualization.

📌 Feel free to contribute or suggest improvements!

🤝 Contributing
Want to improve this project? Feel free to fork, clone, and submit a pull request!

📧 For any questions, reach out or open an issue!

🚀 Happy Sniffing! 🕵️‍♂️💻

