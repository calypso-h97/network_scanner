from scapy.all import ARP, Ether, srp
import socket
from mac_vendor_lookup import MacLookup
import json

class NetworkScanner:

    def __init__ (self, network="192.168.0.1/24", iface="en0"):
        self.network = network
        self.iface = iface
        self.devices = []

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
    
    def display_results(self):
        """Displays the scanned devices and their details."""
        print("\nDevices found:")
        for device in self.devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}, Vendor: {device['Vendor']}")
            print(f"Open Ports: {device.get('Open Ports', [])}\n")
    
    def save_results_to_json(self):
        """
        Saves results to JSON
        """

        with open("network_scan_results.json", "w") as file:
            json.dump(self.devices, file, indent=4)
        print("Result saved to network_scan_results.json")

if __name__ == "__main__":
    
    scanner = NetworkScanner()
    scanner.scan_network()
    scanner.scan_ports(ports=[22, 80, 443, 8080])
    scanner.display_results()
    scanner.save_results_to_json()