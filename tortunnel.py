import os
import random
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

TOR_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051 
TOR_PASSWORD = ""

TUNNEL_ACTIVATED = False
FIREWALL_BACKEND = None

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
            print(f"[-] Command execution failed: {' '.join(cmd_list)} | Error: "
                  f"{e.stderr.decode().strip()}")
        return False

    except Exception as e:
        if not suppress_errors:
            print(f"[-] System error executing command {' '.join(cmd_list)}: {e}")
        return False
               
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
        
    for username in ["tor", "debian-tor", "tor-anonymity", "nobody"]:
        try:
            import pwd
            pwd.getpwnam(username)
            return username
        except KeyError:
            continue
    return "tor"

def is_tor_responsive():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((TOR_HOST, TOR_CONTROL_PORT))
            s.sendall(f'AUTHENTICATE "{TOR_PASSWORD}"\r\n'.encode('utf-8'))
            response = s.recv(1024).decode('utf-8')
            return "250" in response
    except Exception:
        return False

def is_connection_alive(target_url="http://1.1.1.1", timeout=4):
    try:
        # Формируем объект запроса и явно указываем метод HEAD
        req = urllib.request.Request(
            target_url, 
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/21000101 Firefox/115.0"},
            method="HEAD"
        )
        # Открываем соединение внутри контекстного менеджера с таймаутом
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status < 400
    except (urllib.error.URLError, Exception):
        return False

def setup_traffic_tunnel():
    global TUNNEL_ACTIVATED, FIREWALL_BACKEND

    print("[*] Checking subsystem readiness...")
    if not is_tor_responsive():
        print(f"[-] Critical Error: Tor daemon is not responding on port {TOR_CONTROL_PORT}!")
        print("[!] Check if Tor is running and ControlPort is enabled. Script stopped, firewall unchanged.")
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
            ["nft", "add", "rule", "ip", "nat", "OUTPUT", "skuid", tor_user, "return"], # Allow Tor daemon native traffic
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
            ["nft", "add", "rule", "ip", "filter", "OUTPUT", "ip", "protocol", "udp", "drop"], # Block QUIC/UDP leaks

            ["nft", "add", "table", "ip6", "filter"],
            ["nft", "add", "chain", "ip6", "filter", "OUTPUT", "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"],
            ["nft", "add", "rule", "ip6", "filter", "OUTPUT", "drop"]
        ]
    
    elif FIREWALL_BACKEND == "iptables":
        print("[*] Applying rules for iptables...")
        run_command(["modprobe", "iptable_nat"])
        run_command(["modprobe", "xt_REDIRECT"])

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
            run_command(["nft", "delete", "table", "ip", "nat"])
            run_command(["nft", "delete", "table", "ip", "filter"])
            run_command(["nft", "delete", "table", "ip6", "filter"])
        elif FIREWALL_BACKEND == "iptables":
            run_command(["iptables", "-t", "nat", "-F", "OUTPUT"])
            run_command(["iptables", "-F", "OUTPUT"])
            run_command(["ip6tables", "-P", "OUTPUT", "ACCEPT"])
            run_command(["ip6tables", "-F", "OUTPUT"])
        print("[+] Network successfully restored to its original state.")
        print("="*65+"\n")
    else:
        print("\n[*] No firewall modifications detected. Clean up skipped.")

def request_ip_rotation(host=TOR_HOST, port=TOR_CONTROL_PORT, password=TOR_PASSWORD):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))

            auth_command = f'AUTHENTICATE "{password}"\r\n'.encode('utf-8')
            s.sendall(auth_command)

            response = s.recv(1024).decode('utf-8')
            if "250" not in response:
                print(f"[-] Authentication failed. Response: {response.strip()}")
                return False

            s.sendall(b"SIGNAL NEWNYM\r\n")
            response_sig = s.recv(1024).decode('utf-8')
            if "250" not in response_sig:
                print(f"[-] Tor rejected NEWNYM signal: {response_sig.strip()}")
                return False

            s.sendall(b"SIGNAL CLEARDNSCACHE\r\n")
            s.recv(1024)

            print("[+] NEWNYM signal accepted. Tor circuit is updating.")
            return True
    except Exception as e:
        print(f"[-] Socket error during rotation: {e}")
        return False

def start_automation_loop(min_interval, max_interval):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(""+"="*65)
    print(f"[*] Launching TorTunnel. Interval: {min_interval}s to {max_interval}s.")
    print("[*] Press Ctrl+C to stop\n" + "="*65)
    
    setup_traffic_tunnel()

    iteration = 1
    try:
        while True:
            print(f"\n[Iteration #{iteration}] Requesting IP rotation...")

            success = request_ip_rotation()
            if success:
                time.sleep(5)
                
                if not is_connection_alive():
                    print("[!] Encounted a 'dead' or censored Tor node. Immediate re-rotation forced...")
                    print("[*] Temporarily disabling tunnel to fetch fresh circuit configuration...")
                    
                    clear_traffic_tunnel()
                    request_ip_rotation()

                    print("[*] Waiting for Tor circuit rebuild via direct connection...")
                    time.sleep(8)

                    print("[*] Re-enabling firewall protection...")
                    setup_traffic_tunnel()

                    continue

                sleep_time = random.randint(min_interval, max_interval)
                forced_rotation = False
                
                seconds_passed = 0
                for remaining in range(sleep_time, 0, -1):
                    sys.stdout.write(f"\r[~] Next IP rotation in: {remaining}s...   ")
                    sys.stdout.flush()
                    time.sleep(1)
                    seconds_passed += 1
                    
                    if seconds_passed > 5 and seconds_passed % 10 == 0:
                        if not is_connection_alive():
                            print("\n[!] Connection lost (Tor node died during standby)! Forcing rotation...")
                            forced_rotation = True
                            break
                
                if forced_rotation:
                    print("[*] Triggering emergency tunnel reset for connection recovery...")
                    clear_traffic_tunnel()
                    request_ip_rotation()
                    time.sleep(8)
                    setup_traffic_tunnel()
                    continue
                    
                sys.stdout.write("\r[+] Standby finished. Requesting new IP address...\n")
                sys.stdout.flush()
                iteration += 1
            else:
                print("[!] Unable to communicate with Tor. Retrying in 10 seconds...")
                time.sleep(10)

    except KeyboardInterrupt:
        print("\n[*] Automation stopped by user.\n")
    finally:
        clear_traffic_tunnel()

if __name__ == "__main__":
    start_automation_loop(min_interval=15, max_interval=45)
