
# ⚡ AirStrike

A PyQt5 GUI toolkit for wireless network penetration testing.  
It wraps common aircrack-ng tools (airodump-ng, aireplay-ng, and aircrack-ng) in a clean graphical interface with green console-style output.


Features

- Scan Networks  
  Discover nearby WiFi access points and display details in a live table.

- Packet Capture  
  Capture packets from selected APs and save them into .cap files for cracking.

- Deauthentication Attacks  
  Launch deauth packets against access points or specific clients.

- Aircrack-ng Integration  
  Crack captured WiFi handshakes using a wordlist (default: rockyou.txt).

- Modern Dark GUI  
  Sleek PyQt5 interface with vertical tabs, neon buttons, and green output.


Requirements

- Python 3.8 or newer
- PyQt5 (install via pip)
- aircrack-ng toolkit (system package — not a Python package)
- Wireless Adapter

Install Python dependencies:

pip install -r requirements.txt


Install aircrack-ng on Debian/Ubuntu/Kali:

sudo apt update && sudo apt install aircrack-ng


Usage

The application typically requires root privileges to access monitor-mode wireless interfaces.

Run the tool:

sudo python3 AirStrike.py


Typical workflow:

1. Scan Networks: Click Scan Networks to list available APs. Select an AP from the table.  
2. Packet Capture: Switch to Packet Capture tab, enter a filename, and click Start Capture.  
3. Deauth Attack: In the Deauthentication tab, choose a target BSSID and/or client, then send deauth packets.  
4. Crack Handshake: In the Aircrack-ng tab, select your .cap file and wordlist, then click Start Cracking.


Important notes

- airodump-ng, aireplay-ng, and aircrack-ng are system utilities. They must be installed on the OS and typically require root privileges.  
- The GUI reads tool output and displays it in green; the display behavior depends on the versions of the underlying tools.  
- Use this tool only on networks you own or have explicit permission to test. Unauthorized use may be illegal.


Development

Clone the repository and install dependencies:


git clone https://github.com/DevDar678/AirStrike.git

cd AirStrike

pip install -r requirements.txt


License

MIT License © 2025 Sidra Shabbir
