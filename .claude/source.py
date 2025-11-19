#!/usr/bin/env python3
import socket
import struct
import fcntl
import time

SOURCE_PORTS = [
    22, 53, 67, 68, 80, 123, 161, 443, 500, 4500,
    2000, 2001, 2022, 2049, 2222, 5353, 8080
]

CONNECT_PORT = 2024
TIMEOUT = 2.0


def get_interfaces():
    """
    Returns all non-loopback interfaces using SIOCGIFCONF.
    """
    max_bytes = 8096
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array = None

    # Prepare buffer for SIOCGIFCONF
    import array
    array = array.array('B', b'\0' * max_bytes)
    ifconf = struct.pack('iP', max_bytes, array.buffer_info()[0])

    res = fcntl.ioctl(sock.fileno(), 0x8912, ifconf)  # SIOCGIFCONF
    outbytes = struct.unpack('iP', res)[0]
    data = array.tobytes()[:outbytes]

    interfaces = []
    for i in range(0, len(data), 40):  # struct ifreq is 40 bytes on Linux
        name = data[i:i+16].split(b'\0', 1)[0].decode()
        addr = data[i+20:i+24]
        ip = socket.inet_ntoa(addr)
        if name != "lo":
            interfaces.append((name, ip))
    return interfaces


def get_default_gateway():
    """
    Parse /proc/net/route to find the default gateway.
    Returns (gateway_ip, interface_name)
    """
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.strip().split()
            iface, dest, gateway = fields[0], fields[1], fields[2]

            # default route has dest == 0
            if dest == "00000000":
                gw = socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
                return gw, iface

    raise RuntimeError("No default gateway found in /proc/net/route")


def attempt_connect(src_port, dst_ip):
    """
    Bind to a specific source port and attempt a TCP connect.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.bind(("0.0.0.0", src_port))
    except PermissionError:
        return "bind(): permission denied"
    except OSError as e:
        return f"bind(): {e}"

    try:
        sock.connect((dst_ip, CONNECT_PORT))
        return "CONNECTED"
    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        return f"oserror: {e}"
    finally:
        sock.close()


def main():
    gw_ip, gw_iface = get_default_gateway()

    # Find non-lo interface that matches the default route interface
    interfaces = get_interfaces()
    iface_ip = None
    for name, ip in interfaces:
        if name == gw_iface:
            iface_ip = ip
            break

    print(f"Default gateway: {gw_ip}")
    print(f"Interface: {gw_iface}")
    if iface_ip:
        print(f"Interface IP: {iface_ip}")
    print(f"Testing TCP → {gw_ip}:{CONNECT_PORT}\n")

    for sp in SOURCE_PORTS:
        result = attempt_connect(sp, gw_ip)
        print(f"Source port {sp:<5} → {result}")


if __name__ == "__main__":
    main()
