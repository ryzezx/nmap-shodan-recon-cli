import subprocess
import json
import argparse
import os
import shodan
from tabulate import tabulate

def run_nmap(target):
    try:
        output = subprocess.check_output(
            ["nmap", "-sV", "-oX", "-", target],
            stderr=subprocess.DEVNULL
        ).decode()
    except Exception as e:
        print(f"[!] Error running Nmap: {e}")
        return []

    import xml.etree.ElementTree as ET
    root = ET.fromstring(output)
    results = []

    for host in root.findall("host"):
        for port in host.find("ports").findall("port"):
            port_id = port.get("portid")
            proto = port.get("protocol")
            state = port.find("state").get("state")
            service_elem = port.find("service")
            service = service_elem.get("name")
            version = service_elem.get("version") or "-"
            results.append({
                "port": f"{port_id}/{proto}",
                "state": state,
                "service": service,
                "version": version
            })
    return results

def run_shodan_lookup(target):
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("[!] SHODAN_API_KEY environment variable not set.")
        return {}
    try:
        api = shodan.Shodan(api_key)
        host = api.host(target)
        return {
            "ports": host.get("ports", []),
            "tags": host.get("tags", []),
            "vulns": host.get("vulns", [])
        }
    except shodan.APIError as e:
        print(f"[!] Shodan API Error: {e}")
        return {}

def pretty_print(target, nmap_results, shodan_results):
    print(f"\nTarget IP: {target}\n")

    print("🔍 Nmap Scan:")
    if nmap_results:
        table = [
            [entry["port"], entry["state"], entry["service"], entry["version"]]
            for entry in nmap_results
        ]
        print(tabulate(table, headers=["PORT", "STATE", "SERVICE", "VERSION"]))
    else:
        print("No results from Nmap.")

    print("\n🛰️ Shodan Data:")
    if shodan_results:
        print(f"Open ports (Shodan): {shodan_results.get('ports', [])}")
        print(f"Tags: {shodan_results.get('tags', [])}")
        print(f"Vulns: {shodan_results.get('vulns', [])}")
    else:
        print("No results from Shodan.")

def main():
    parser = argparse.ArgumentParser(description="🛰️ Nmap + Shodan Recon CLI")
    parser.add_argument("--target", required=True, help="IP to scan")
    args = parser.parse_args()

    nmap_results = run_nmap(args.target)
    shodan_results = run_shodan_lookup(args.target)

    pretty_print(args.target, nmap_results, shodan_results)

if __name__ == "__main__":
    main()
