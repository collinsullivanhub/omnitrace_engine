import sys
import os
import ctypes
import socket
import urllib.request
import json
from concurrent.futures import ThreadPoolExecutor

# Initialize ANSI console flags on Windows
if sys.platform == 'win32':
    os.system('')

# Soft basic colors using ANSI escape sequences
CLR_HEADER = "\033[96m"       # Soft Cyan
CLR_RESET = "\033[0m"         # Reset
CLR_GREEN = "\033[38;5;150m"  # Soft Green (Responsive, no loss)
CLR_YELLOW = "\033[38;5;216m" # Soft Yellow / Peach (Minor loss / medium latency)
CLR_RED = "\033[38;5;203m"    # Soft Red / Pink (100% loss / timeout)
CLR_GRAY = "\033[90m"         # Dark Gray (Separators)
CLR_BLUE = "\033[38;5;117m"   # Soft Blue (Protocol names & fingerprints)

isp_cache = {}

def is_admin():
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0

def get_isp_and_hostname(ip):
    if ip == "*" or ip == "0.0.0.0":
        return "*", "*"
        
    if ip in isp_cache:
        return isp_cache[ip]
        
    hostname = "*"
    isp_name = "*"
    
    # 1. Try Reverse DNS
    try:
        hostname_info = socket.gethostbyaddr(ip)
        hostname = hostname_info[0]
    except Exception:
        hostname = "No RDNS"
        
    # 2. Try HTTP Geolocation / ISP lookup
    try:
        url = f"http://ip-api.com/json/{ip}?fields=isp,org,as"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=0.5) as response:
            data = json.loads(response.read().decode())
            isp_name = data.get('isp', data.get('org', '*'))
            if not isp_name:
                isp_name = "*"
    except Exception:
        # Fallback to parsing RDNS domain name
        if hostname != "No RDNS" and hostname != "*":
            parts = hostname.split('.')
            if len(parts) >= 2:
                isp_name = f"{parts[-2].upper()} (via RDNS)"
            else:
                isp_name = "Unknown"
        else:
            isp_name = "Unknown"
            
    isp_cache[ip] = (isp_name, hostname)
    return isp_name, hostname

def run_trace(target, max_hops=30, timeout_ms=1000, probes_per_hop=3):
    print(f"Tracing route to {CLR_HEADER}{target}{CLR_RESET} (max_hops={max_hops}, timeout={timeout_ms}ms, probes={probes_per_hop})...")
    print(f"Current process has Admin/Root privileges: {CLR_GREEN if is_admin() else CLR_RED}{is_admin()}{CLR_RESET}")
    
    try:
        import omnitrace_engine
    except ImportError as e:
        print(f"{CLR_RED}Error importing omnitrace_engine: {e}{CLR_RESET}")
        sys.exit(1)
        
    try:
        results = omnitrace_engine.trace(target, max_hops, timeout_ms, probes_per_hop)
        
        # Concurrently resolve ISPs and Hostnames to prevent blocking
        ips = [r['ip'] for r in results]
        with ThreadPoolExecutor(max_workers=10) as executor:
            resolved = list(executor.map(get_isp_and_hostname, ips))
            
        for i, r in enumerate(results):
            r['isp'], r['hostname'] = resolved[i]
            
        # Header formatting
        header = f"\n{CLR_HEADER}Hop | Proto | Device Fingerprint    | ISP / Network Provider     | Responder IP     | Min RTT | Max RTT | Avg RTT | Loss %{CLR_RESET}"
        separator = f"{CLR_GRAY}" + "-" * 142 + f"{CLR_RESET}"
        
        print(header)
        print(separator)
        
        for r in results:
            hop = r['hop']
            ip = r['ip']
            proto = r['proto']
            device = r['device']
            isp = r['isp']
            min_ms = f"{r['min_ms']:.2f}" if r['min_ms'] > 0 else "0.00"
            max_ms = f"{r['max_ms']:.2f}" if r['max_ms'] > 0 else "0.00"
            avg_ms = f"{r['avg_ms']:.2f}" if r['avg_ms'] > 0 else "0.00"
            loss_pct = r['loss_pct']
            loss = f"{loss_pct:.1f}%"
            
            # Select color scheme based on hop status
            if ip == "*":
                color = CLR_RED
            elif loss_pct > 0.0:
                color = CLR_YELLOW
            else:
                color = CLR_GREEN
            
            # Apply colors to fields
            hop_str = f"{color}{hop:<3}{CLR_RESET}"
            proto_str = f"{CLR_BLUE}{proto:<5}{CLR_RESET}" if proto != "*" else f"{CLR_RED}*    {CLR_RESET}"
            device_str = f"{CLR_BLUE}{device:<22}{CLR_RESET}" if device != "*" else f"{CLR_RED}*                     {CLR_RESET}"
            isp_str = f"{CLR_BLUE}{isp:<26}{CLR_RESET}" if isp != "*" else f"{CLR_RED}*                         {CLR_RESET}"
            ip_str = f"{color}{ip:<16}{CLR_RESET}"
            min_str = f"{color}{min_ms:>7}{CLR_RESET}"
            max_str = f"{color}{max_ms:>7}{CLR_RESET}"
            avg_str = f"{color}{avg_ms:>7}{CLR_RESET}"
            loss_str = f"{color}{loss:>6}{CLR_RESET}"
            
            print(f"{hop_str} | {proto_str} | {device_str} | {isp_str} | {ip_str} | {min_str} | {max_str} | {avg_str} | {loss_str}")
            
    except PermissionError as pe:
        print(f"\n{CLR_RED}[PermissionError] {pe}{CLR_RESET}")
        print("Please run this shell/script as Administrator (on Windows) or using sudo (on Linux/macOS).")
    except Exception as ex:
        print(f"\n{CLR_RED}[Error] {ex}{CLR_RESET}")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    run_trace(target)
