import os
import random
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import hashlib
import base64

TOR_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051 
TOR_SOCKS_PORT = 9050
TOR_PASSWORD = ""

TUNNEL_ACTIVATED = False
FIREWALL_BACKEND = None

BRIDGES_URL = "https://raw.githubusercontent.com/neeitr0n/TorTunnel-bridges/refs/heads/main/bridges_encoded.txt"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_FILE_PATH = os.path.join(SCRIPT_DIR, "bridges.hash")

TORRC_PATH = "/etc/tor/torrc"
START_MARKER = "# === TorTunnel AutoConfig ==="
END_MARKER = "# === End TorTunnel AutoConfig ==="

def run_command(cmd_list, suppress_errors=False):
    try:
        subprocess.run(
            cmd_list,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return True
    except subprocess.CalledProcessError as e:
        if not suppress_errors:
            print(f"[-] Command execution failed: {' '.join(cmd_list)} | Error: {e.stderr.decode().strip()}")
        return False
    except Exception as e:
        if not suppress_errors:
            print(f"[-] System error executing command {' '.join(cmd_list)}: {e}")
        return False

def load_local_hash():
    if os.path.exists(HASH_FILE_PATH):
        try:
            with open(HASH_FILE_PATH, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return None
    return None 

def save_local_hash(new_hash):
    try:
        with open(HASH_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(new_hash)
    except Exception as e:
        print(f"[-] Warning: Failed to save bridge cache hash: {e}")

def fetch_remote_bridges():
    print("[*] Connecting to remote repository to verify bridge status...")
    try:
        req = urllib.request.Request(BRIDGES_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            encoded_content = response.read()

        remote_hash = hashlib.sha256(encoded_content).hexdigest()
        local_hash = load_local_hash()

        if local_hash == remote_hash:
            print("[+] Bridge database is up-to-date. No changes detected.")
            return None, remote_hash

        if local_hash is None:
            print("[*] Initial launch or empty cache detected. Fetching bridges...")
        else:
            print("[!] Remote bridge database update detected! Syncing...")

        decoded_bytes = base64.b64decode(encoded_content)
        all_bridges = decoded_bytes.decode('utf-8').splitlines()
        
        valid_bridges = []
        for b in all_bridges:
            line = b.strip()

            if not line.startswith("Bridge"):
                continue

            if "8.8.8.8" in line or "10.122." in line:
                continue
            valid_bridges.append(line)

        if not valid_bridges:
            print("[-] Error: Failed to parse valid bridge descriptors from the remote payload.")
            return None, None

        print(f"[+] Successfully decrypted and filtered {len(valid_bridges)} valid bridges into memory.")
        return valid_bridges, remote_hash

    except urllib.error.URLError as e:
        print(f"[-] Network connection failure during bridge sync: {e.reason}")
        return None, None
    except Exception as e:
        print(f"[-] Critical execution fault during bridge sync: {e}")
        return None, None
              
def setup_torrc_config(torrc_path=TORRC_PATH):
    try:
        if not os.path.exists(torrc_path):
            print(f"[-] Error: {torrc_path} not found.")
            return False
            
        with open(torrc_path, 'r', encoding='utf-8') as f:
            content = f.read()

        if START_MARKER in content and END_MARKER in content:
            print("[*] Found existing TorTunnel configuration block. Sanitizing...")
            parts = content.split(START_MARKER)
            before_block = parts[0]
            after_block = parts[1].split(END_MARKER)[1]
            clean_base_content = before_block.strip() + "\n" + after_block.strip()
        else:
            lines = content.splitlines()
            cleaned_lines = []
            conflicting_keys = [
                "SOCKSPort", "TransPort", "DNSPort", "ControlPort", 
                "MaxCircuitDirtiness", "NewCircuitPeriod", 
                "EnforceDistinctSubnets", "VirtualAddrNetworkIPv4", "AutomapHostsOnResolve", "UseBridges"
            ]
            for line in lines:
                strip_line = line.strip()
                if any(strip_line.startswith(key) for key in conflicting_keys) and not strip_line.startswith("#"):
                    cleaned_lines.append(f"# Commented out by TorTunnel to avoid conflict:\n# {line}")
                else:
                    cleaned_lines.append(line)
            clean_base_content = "\n".join(cleaned_lines)

            backup_path = torrc_path + ".bak"
            shutil.copyfile(torrc_path, backup_path)
            print(f"[+] Original torrc backup successfully created at: {backup_path}")

        bridges_list, remote_hash = fetch_remote_bridges()

        if bridges_list is not None:
            save_local_hash(remote_hash)
        else:
            if START_MARKER in content:
                block_content = content.split(START_MARKER)[1].split(END_MARKER)[0]
                bridges_list = []
                for line in block_content.splitlines():
                    line_s = line.strip()
                    if line_s.startswith("Bridge obfs4"):
                        bridges_list.append(line_s)
                    elif line_s.startswith("# Bridge obfs4"):
                        cleaned_bridge = line_s.replace("# [Active] ", "").replace("# ", "", 1)
                        if cleaned_bridge.startswith("Bridge obfs4"):
                            bridges_list.append(cleaned_bridge)
            else:
                bridges_list = []

        bridges_section_lines = ["\n# --- AUTOMATICALLY MANAGED POOL ---"]
        if bridges_list:
            count_to_select = random.randint(5, 10)
            active_bridges = random.sample(bridges_list, min(count_to_select, len(bridges_list)))
            active_set = set(active_bridges)

            for bridge in bridges_list:
                if bridge in active_set:
                    # Оставляем активным для Tor
                    bridges_section_lines.append(bridge)
                else:
                    # Остальные комментируем, чтобы Tor их не опрашивал при старте
                    bridges_section_lines.append(f"# {bridge}")
            
            bridges_section = "\n" + "\n".join(bridges_section_lines)
            print(f"[+] Activated {len(active_set)} random bridges. {len(bridges_list) - len(active_set)} backup bridges are commented out.")
        else:
            bridges_section = ""

        config_block = (
            f"\n{START_MARKER}\n"
            "SOCKSPort 127.0.0.1:9050\n"
            "TransPort 127.0.0.1:9040\n"
            "DNSPort 127.0.0.1:5353\n"
            "ControlPort 127.0.0.1:9051\n"
            "MaxCircuitDirtiness 30\n"
            "NewCircuitPeriod 15\n"
            "EnforceDistinctSubnets 1\n"
            "VirtualAddrNetworkIPv4 10.192.0.0/10\n"
            "AutomapHostsOnResolve 1\n"
            "UseBridges 1\n"
            "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"
            f"{bridges_section}\n"
            f"{END_MARKER}\n"
        )
                       
        final_content = clean_base_content.strip() + "\n" + config_block

        with open(torrc_path, 'w', encoding='utf-8') as f:
            f.write(final_content)
            
        print("[+] torrc updated successfully. Applying changes...")
        if run_command(["systemctl", "restart", "tor.service"]):
            print("[+] Tor service restarted with new configuration.")
            time.sleep(3)
            return True
        else:
            print("[-] Failed to restart Tor service via systemctl.")
            return False
            
    except PermissionError:
        print("[-] Permission denied. Please run the script with sudo (needed to modify torrc).")
        return False
    except Exception as e:
        print(f"[-] Error updating torrc: {e}")
        return False

def restore_all_bridges_in_torrc(torrc_path=TORRC_PATH):
    print("[*] Restoring all backup bridges in torrc (uncommenting)...")
    try:
        if not os.path.exists(torrc_path):
            return
            
        with open(torrc_path, "r", encoding="utf-8") as f:
            content = f.read()

        if START_MARKER in content and END_MARKER in content:
            parts = content.split(START_MARKER)
            before_block = parts[0]
            block_and_after = parts[1].split(END_MARKER)
            block_content = block_and_after[0]
            after_block = block_and_after[1]

            cleaned_block_lines = []
            for line in block_content.splitlines():
                line_s = line.strip()
                # Раскомментируем только те мосты, перед которыми мы ставили знак решетки #
                if line_s.startswith("# Bridge obfs4"):
                    cleaned_block_lines.append(line_s.replace("# ", "", 1))
                else:
                    cleaned_block_lines.append(line)

            restored_block = "\n".join(cleaned_block_lines)
            final_content = f"{before_block.strip()}\n{START_MARKER}\n{restored_block}\n{END_MARKER}\n{after_block.strip()}\n"

            with open(torrc_path, "w", encoding="utf-8") as f:
                f.write(final_content)
            print("[+] All backup bridges successfully uncommented in torrc.")
    except Exception as e:
        print(f"[-] Failed to restore torrc bridges during cleanup: {e}")

def detect_firewall_backend():
    if shutil.which("nft"):
        return "nftables"
    elif shutil.which("iptables"):
        return "iptables"
    else:
        return None

def detect_tor_user():
    try:
        res = subprocess.run(["ps", "-C", "tor", "-o", "user="], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        user = res.stdout.strip()
        if user:
            return user
    except Exception:
        pass
        
    for username in ["debian-tor", "tor", "tor-anonymity", "nobody"]:
        try:
            import pwd
            pwd.getpwnam(username)
            return username
        except KeyError:
            continue
    return "tor"

def send_tor_control_command(command):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((TOR_HOST, TOR_CONTROL_PORT))
            s.sendall(f'AUTHENTICATE "{TOR_PASSWORD}"\r\n'.encode('utf-8'))
            response = s.recv(1024).decode('utf-8')
            if "250" not in response:
                return None, f"Auth failed: {response.strip()}"

            s.sendall(f"{command}\r\n".encode('utf-8'))
            response = s.recv(1024).decode('utf-8')
            return response, None
    except Exception as e:
        return None, str(e)

def is_tor_responsive():
    res, _ = send_tor_control_command("PROTOCOLINFO 1")
    return res is not None and "250" in res

def wait_for_tor_circuit(timeout=90):
    print("[*] Waiting for Tor to establish circuit status via bridges...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        res, _ = send_tor_control_command("GETINFO status/circuit-established")
        if res and "status/circuit-established=1" in res:
            print("[+] Tor network circuit is fully established!")
            return True
        time.sleep(3)
    print("[-] Timeout waiting for Tor circuit.")
    return False

def is_connection_alive(target_url="http://1.1.1.1", timeout=12):
    try:
        req = urllib.request.Request(
            target_url, 
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"},
            method="HEAD"
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status < 400
    except Exception:
        return False

def setup_traffic_tunnel():
    global TUNNEL_ACTIVATED, FIREWALL_BACKEND

    print("[*] Checking subsystem readiness...")
    if not is_tor_responsive():
        print(f"[-] Critical Error: Tor daemon is not responding on port {TOR_CONTROL_PORT}!")
        sys.exit(1)

    FIREWALL_BACKEND = detect_firewall_backend()
    tor_user = detect_tor_user()
    
    print(f"[+] Tor daemon is active and ready.")
    print(f"[*] Firewall engine: {FIREWALL_BACKEND}")
    print(f"[*] Tor process owner: {tor_user}")
    
    if FIREWALL_BACKEND == "nftables":
        print("[*] Applying rules for nftables...")
        run_command(["nft", "delete", "table", "ip", "nat"], suppress_errors=True)
        run_command(["nft", "delete", "table", "ip", "filter"], suppress_errors=True)
        run_command(["nft", "delete", "table", "ip6", "filter"], suppress_errors=True)        
        commands = [
            ["nft", "add", "table", "ip", "nat"],
            ["nft", "add", "chain", "ip", "nat", "OUTPUT", "{", "type", "nat", "hook", "output", "priority", "filter", ";", "}"],  
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "skuid", tor_user, "return"],
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "ip", "daddr", "192.168.0.0/16", "return"],
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "udp", "dport", "53", "redirect", "to", ":5353"],
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "tcp", "dport", "53", "redirect", "to", ":5353"],
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "oif", "lo", "return"],
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "ip", "protocol", "tcp", "redirect", "to", ":9040"],

            ["nft", "add", "table", "ip", "filter"],
            ["nft", "add", "chain", "ip", "filter", "OUTPUT", "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"],
            ["nft", "add", "rule", "ip", "filter", "OUTPUT", "skuid", tor_user, "accept"],
            ["nft", "add", "rule", "ip", "filter", "OUTPUT", "ip", "daddr", "192.168.0.0/16", "accept"],
            ["nft", "add", "rule", "ip", "filter", "OUTPUT", "oif", "lo", "accept"],
            ["nft", "add", "rule", "ip", "filter", "OUTPUT", "udp", "dport", "53", "accept"], 
            ["nft", "add", "rule", "ip", "filter", "OUTPUT", "ip", "protocol", "udp", "drop"],

            ["nft", "add", "table", "ip6", "filter"],
            ["nft", "add", "chain", "ip6", "filter", "OUTPUT", "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"],
            ["nft", "add", "rule", "ip6", "filter", "OUTPUT", "drop"]
        ]
    elif FIREWALL_BACKEND == "iptables":
        print("[*] Applying rules for iptables...")
        run_command(["modprobe", "iptable_nat"], suppress_errors=True)
        run_command(["modprobe", "xt_REDIRECT"], suppress_errors=True)
        commands = [
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", tor_user, "-j", "RETURN"],                
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-d", "192.168.0.0/16", "-j", "RETURN"],
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"],
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"],
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-o", "lo", "-j", "RETURN"],
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "9040"],
            
            ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", tor_user, "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-d", "192.168.0.0/16", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-p", "udp", "-j", "DROP"],
            
            ["ip6tables", "-P", "OUTPUT", "DROP"]
        ]
    else:
        print("[-] Critical Error: No compatible firewall backend found!\n")
        sys.exit(1)    

    for cmd in commands:
        if not run_command(cmd):
            print("[-] Critical error during firewall setup. Rolling back.")
            clear_traffic_tunnel()
            sys.exit(1)
    
    TUNNEL_ACTIVATED = True
    print("[+] Tunnel successfully activated. IPv6 disabled, leaks blocked!")
    print("="*65)

def clear_traffic_tunnel():
    global TUNNEL_ACTIVATED, FIREWALL_BACKEND
    if TUNNEL_ACTIVATED:
        print("="*65)
        print(f"[*] Deactivating tunnel: clearing {FIREWALL_BACKEND} rules...")
        if FIREWALL_BACKEND == "nftables":
            run_command(["nft", "delete", "table", "ip", "nat"], suppress_errors=True)
            run_command(["nft", "delete", "table", "ip", "filter"], suppress_errors=True)
            run_command(["nft", "delete", "table", "ip6", "filter"], suppress_errors=True)
        elif FIREWALL_BACKEND == "iptables":
            run_command(["iptables", "-t", "nat", "-F", "OUTPUT"], suppress_errors=True)
            run_command(["iptables", "-F", "OUTPUT"], suppress_errors=True)
            run_command(["ip6tables", "-P", "OUTPUT", "ACCEPT"], suppress_errors=True)
            run_command(["ip6tables", "-F", "OUTPUT"], suppress_errors=True)
        TUNNEL_ACTIVATED = False
        print("[+] Network successfully restored to its original state.")
        print("="*65+"\n")

def request_ip_rotation():
    res, err = send_tor_control_command("SIGNAL NEWNYM")
    if res and "250" in res:
        print("[+] NEWNYM signal accepted. Tor circuit is updating.")
        send_tor_control_command("SIGNAL CLEARDNSCACHE")
        return True
    print(f"[-] Tor rejected NEWNYM signal: {err}")
    return False

def start_automation_loop(check_interval=15):
    if os.getuid() != 0:
        print("[-] Critical Error: This script must be executed with root (sudo) privileges.")
        sys.exit(1)

    if not setup_torrc_config():
        print("[-] Initial Tor configuration failed. Exiting.")
        return

    os.system('cls' if os.name == 'nt' else 'clear')
    print("="*65)
    print("[*] Launching TorTunnel Watchdog Mode (Bridges Compatible).")
    print(f"[*] Connection monitoring interval: every {check_interval} seconds.")
    print("[*] Press Ctrl+C to stop and clear firewall rules\n" + "="*65)
    
    wait_for_tor_circuit()
    setup_traffic_tunnel()
    
    print("\n[+] Tunnel is ACTIVE. Your traffic is now securely routed through Tor.")
    print("[*] System status: Operational. Monitoring integrity...")

    try:
        while True:
            time.sleep(check_interval)
            
            if not is_connection_alive():
                timestamp = time.strftime('%H:%M:%S')
                print(f"\n[{timestamp}] [!] Connection dropped! Initiating emergency recovery...")
                
                clear_traffic_tunnel()
                
                print("[*] Rotating bridges from local pool to establish a new circuit...")
                setup_torrc_config()
                request_ip_rotation() 
                
                if wait_for_tor_circuit(timeout=90):
                    time.sleep(5)
                    setup_traffic_tunnel()
                    new_timestamp = time.strftime('%H:%M:%S')
                    print(f"[{new_timestamp}] [+] Connection restored. Tunnel is ACTIVE again.")
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] [-] Recovery failed. Retrying in next cycle...")
                    
    except KeyboardInterrupt:
        print("\n\n[*] Automation stopped by user.")
    finally:
        print("[*] Cleaning up firewall rules before exit...")
        clear_traffic_tunnel()
        restore_all_bridges_in_torrc()
        print("[+] System network restored to original state.")

if __name__ == "__main__":
    start_automation_loop(check_interval=15)
