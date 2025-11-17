#!/usr/bin/env python3
import socket
import concurrent.futures
import errno

# ---- Ports to test ----
KNOWN_PORTS = [
    #443, 6443, 9000, 9001, 9901,
    #10250, 10255, 10257, 10259,
    #15000, 15001, 15004, 15010, 15014,
    #2024,
] + list(range(1024, 4096))

# -------------------------------------------------------------------
# Extract first non-lo interface with fe80::/10 address
# -------------------------------------------------------------------
def get_linklocal_iface():
    with open("/proc/net/if_inet6") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue

            raw_addr, _, _, _, _, iface = parts
            if iface == "lo":
                continue

            ipv6 = ":".join(raw_addr[i:i+4] for i in range(0, 32, 4))

            if ipv6.lower().startswith("fe80"):
                return ipv6, iface

    raise RuntimeError("No link-local IPv6 interface found")


# -------------------------------------------------------------------
# Attempt TCP connect, classify outcome
# -------------------------------------------------------------------
def check_port(addr, port, iface, timeout=1.0):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    target = (addr, port, 0, socket.if_nametoindex(iface))

    try:
        sock.connect(target)
        sock.close()
        return port, "OPEN"
    except socket.timeout:
        return port, "TIMEOUT"
    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            return port, "CLOSED"
        elif e.errno == errno.EHOSTUNREACH:
            return port, "UNREACHABLE"
        else:
            return port, f"OTHER_ERROR({e.errno})"
    except Exception as e:
        return port, f"ERROR({repr(e)})"


# -------------------------------------------------------------------
# Main scanner
# -------------------------------------------------------------------
def main():
    linklocal, iface = get_linklocal_iface()
    print(f"[+] Interface: {iface}")
    print(f"[+] Link-local: {linklocal}%{iface}")

    target = "::1"
    print(f"[+] Scanning {target}%{iface} across {len(KNOWN_PORTS)} ports...\n")

    results = {}

    # multithreading
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futs = {
            executor.submit(check_port, target, port, iface): port
            for port in KNOWN_PORTS
        }

        for fut in concurrent.futures.as_completed(futs):
            port, status = fut.result()
            results[port] = status
            #print(f"{port:5d} → {status}")

    print("\n=== SUMMARY ===")
    for p in sorted(results):
        if results[p] != "CLOSED":
            print(f"{p:5d} : {results[p]}")


if __name__ == "__main__":
    main()
