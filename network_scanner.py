from scapy.all import ARP, Ether, srp
import socket
from mac_vendor_lookup import MacLookup
import shodan
import json

class NetworkScanner:


    def __init__ (self, network="192.168.0.1/24", iface="en0", shodan_api_key = None):
        self.network = network
        self.iface = iface
        self.devices = []
        self.shodan_api_key = shodan_api_key
        self.shodan_client = shodan.Shodan(shodan_api_key) if shodan_api_key else None

    def scan_network(self):
        """
        Scans the network and returns a list of devices.
        """
        print(f"Scanning network: {self.network}")
        arp_request = ARP(pdst=self.network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send packets and receive responses
        result = srp(packet, iface=self.iface, timeout=2, verbose=0)[0]

        for sent, received in result:
            self.devices.append({
                'IP': received.psrc,
                'MAC': received.hwsrc,
                'Vendor': self.get_mac_vendor(received.hwsrc)
            })

    def scan_ports(self, ports=[22, 80, 443]):
        """
        Scanning specified ports on device
        """
        
        for device in self.devices:
            ip = device['IP']
            open_ports = []
            for port in ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                except Exception:
                    pass
            device['Open Ports'] = open_ports

    def get_mac_vendor(self, mac):
        """
        Getting device vendor by MAC-address
        """
        try:
            return MacLookup().lookup(mac)
        except Exception:
            return "Unknown vendor"
        
    def check_vulnerabilities(self):
        if not self.shodan_client:
            print("Shodan API key is not provided.")
            return

        print("Checking vulnerabilities with Shodan...")
        for device in self.devices:
            ip = device['IP']
            try:
                result = self.shodan_client.host(ip)
                device['Shodan'] = {
                    'OS': result.get('os'),
                    'Vulnerabilities': result.get('vulns', []),
                    'Ports': result.get('ports', [])
                }
            except shodan.APIError as e:
                print(f"Shodan error for {ip}: {e}")
    
    def display_results(self):
        """Displays the scanned devices and their details."""
        print("\nDevices found:")
        for device in self.devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}, Vendor: {device['Vendor']}")
            print(f"Open Ports: {device.get('Open Ports', [])}\n")
            if 'Shodan' in device:
                print(f"Shodan Data: {device['Shodan']}")
            print()
    
    def save_results_to_json(self):
        """
        Saves results to JSON
        """

        with open("network_scan_results.json", "w") as file:
            json.dump(self.devices, file, indent=4)
        print("Result saved to network_scan_results.json")

if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="Network scanner with optional Shodan integration")
    parser.add_argument("--mode", choices=["local", "public"], default="local", help="Choose scanning mode: 'local' for local network or 'public' for Shodan public IP scanning")
    parser.add_argument("--shodan_api_key", help="Shodan API key (required for public mode).", default=None)
    parser.add_argument("--network", help="Network range to scan (default: 192.168.0.1/24).", default="192.168.0.1/24")
    args = parser.parse_args()
    SHODAN_API_KEY = "your_shodan_api_key"

    
    scanner = NetworkScanner(network=args.network, shodan_api_key=args.shodan_api_key if args.mode == "public" else None)

    if args.mode == "local":
        scanner.scan_network()
        scanner.scan_ports(ports=[22, 80, 443, 8080])
    elif args.mode == "public":
        if not args.shodan_api_key:
            print("Shodan API key is required for public mode.")
            exit(1)
        scanner.scan_network()
        scanner.check_vulnerabilities()

    scanner.display_results()
    scanner.save_results_to_json()