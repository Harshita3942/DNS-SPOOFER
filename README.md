# DNS Spoofer

A Python-based DNS spoofer that intercepts and modifies DNS responses to redirect traffic to a specified IP address. This tool is for educational purposes only.

## Features
- Intercepts DNS responses using `scapy` and `netfilterqueue`.
- Spoofs responses for a specified domain to redirect traffic.
- Easy to configure for custom domains and IPs.

## Prerequisites
- Python 3.x
- `scapy` library
- `netfilterqueue` library
- `iptables` (Linux only)

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/dns-spoofer.git
    cd dns-spoofer
    ```

2. Install the required Python libraries:
    ```bash
    pip install scapy netfilterqueue
    ```

3. Set up `iptables` to redirect DNS traffic to the netfilter queue:
    ```bash
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
    ```

4. Run the script:
    ```bash
    sudo python3 dns_spoofer.py
    ```

5. When you're done, reset `iptables`:
    ```bash
    sudo iptables --flush
    ```

## Configuration
Edit the `dns_spoofer.py` file to change the target domain and spoofed IP:
```python
TARGET_DOMAIN = "example.com"  # Replace with the domain you want to spoof
SPOOFED_IP = "192.168.1.100"  # Replace with the desired IP address
