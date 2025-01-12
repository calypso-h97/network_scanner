# Network Scanner

A Python-based network scanner that identifies devices in a local network, scans their open ports, and detects the device vendor based on the MAC address. Optionally, it integrates with Shodan API to find vulnerabilities for public IP addresses.

## Features
- **Local mode**:
  - Scans a specified local network range for active devices.
  - Identifies open ports on each device.
  - Detects the vendor/manufacturer based on the MAC address.
- **Public mode** (Shodan integration):
  - Scans public IPs using Shodan API.
  - Identifies vulnerabilities (CVEs) and other data available from Shodan.

## Requirements
- Python 3.8 or higher
- Virtual environment (optional but recommended)

### Python Libraries
- `scapy`: For sending ARP requests.
- `socket`: For port scanning.
- `mac-vendor-lookup`: For detecting the vendor based on the MAC address.
- `shodan`: For Shodan API integration.

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
1. Run the scanner in **local mode**:
   ```bash
   python3 scanner.py --mode local --network 192.168.0.1/24
   ```

2. Run the scanner in **public mode**:
   ```bash
   python3 scanner.py --mode public --shodan_api_key YOUR_SHODAN_API_KEY --network 8.8.8.8
   ```

### Example Output
```text
Scanning network: 192.168.0.1/24

Devices found:
IP: 192.168.0.102, MAC: aa:bb:cc:dd:ee:ff, Vendor: Apple Inc.
Open Ports: [22, 80]

IP: 192.168.0.105, MAC: 11:22:33:44:55:66, Vendor: Samsung
Open Ports: [80, 443]
Shodan Data: {'OS': 'Linux', 'Vulnerabilities': ['CVE-2023-12345'], 'Ports': [22, 80]}
```

## Configuration
- **Modes**:
  - `local`: Default mode for scanning local networks.
  - `public`: Requires Shodan API key for scanning public IPs.
- **Network range**: Update the `--network` argument to specify the network range or IP.
- **Ports**: Modify the list of ports in the code if needed.

## Future Enhancements
- Add asynchronous port scanning for improved performance.
- Integrate additional APIs (e.g., Censys, ZoomEye).
- Export results in CSV format.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Author
[Your Name](https://github.com/calypso-h97)
