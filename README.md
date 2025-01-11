# Network Scanner

A Python-based network scanner that identifies devices in a local network, scans their open ports, and detects the device vendor based on the MAC address.

## Features
- Scans a specified network range for active devices.
- Identifies open ports on each device.
- Detects the vendor/manufacturer based on the MAC address.
- Displays results in a readable format.
- Saves results to a JSON file.

## Requirements
- Python 3.8 or higher
- Virtual environment (optional but recommended)

### Python Libraries
- `scapy`: For sending ARP requests.
- `socket`: For port scanning.
- `mac-vendor-lookup`: For detecting the vendor based on the MAC address.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/calypso-h97/network_scanner.git
   cd network_scanner
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   venv\Scripts\activate   # On Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the scanner:
   ```bash
   python scanner.py
   ```

2. The script will scan the network range (default: `192.168.0.1/24`), identify devices, scan ports (default: `[22, 80, 443, 8080]`), and display the results.

### Example Output
```text
Scanning network: 192.168.0.1/24

Devices found:
IP: 192.168.0.102, MAC: aa:bb:cc:dd:ee:ff, Vendor: Apple Inc.
Open Ports: [22, 80]

IP: 192.168.0.105, MAC: 11:22:33:44:55:66, Vendor: Samsung
Open Ports: [80, 443]
```

## Configuration
- **Network range**: Update the `network` parameter in the `NetworkScanner` class (default: `192.168.0.1/24`).
- **Interface**: Specify the network interface if necessary (e.g., `en0` on macOS, `eth0` or `wlan0` on Linux).
- **Ports**: Modify the list of ports in the `scan_ports` method.

## Future Enhancements
- Add asynchronous port scanning for improved performance.
- Integrate Shodan API to identify vulnerabilities of devices.
- Export results in CSV format.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Author
[Your Name](https://github.com/calypso-h97)

