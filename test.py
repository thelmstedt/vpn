#!/usr/bin/env python3
import urllib.request
import sys
import json

def check_ip():
    try:
        req = urllib.request.Request(
            'https://ifconfig.co/json',
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                print(f"IP Address: {data['ip']}")
                print(f"Country: {data.get('country', 'Unknown')}")
                print(f"City: {data.get('city', 'Unknown')}")
                return True
            else:
                print(f"Error: Received status code {response.status}")
                return False
    except Exception as e:
        print(f"Error connecting to ifconfig.co: {e}")
        return False

if __name__ == "__main__":
    print("Checking external IP address...")
    if not check_ip():
        sys.exit(1)