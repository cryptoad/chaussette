import socket, ctypes, os

# Constants from linux/netfilter_ipv4/ip_tables.h
SOL_IP = socket.SOL_IP
IPT_SO_GET_INFO = 64            # same as IPT_BASE_CTL
XT_TABLE_MAXNAMELEN = 32
NF_IP_NUMHOOKS = 5

class IPTGetinfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * XT_TABLE_MAXNAMELEN),
        ("valid_hooks", ctypes.c_uint),
        ("hook_entry", ctypes.c_uint * NF_IP_NUMHOOKS),
        ("underflow", ctypes.c_uint * NF_IP_NUMHOOKS),
        ("num_entries", ctypes.c_uint),
        ("size", ctypes.c_uint),
    ]

# Must run as root with CAP_NET_RAW/CAP_NET_ADMIN (gVisor: pass --net-raw).
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
    info = IPTGetinfo()
    info.name = b"nat"  # request info for the nat table
    buf_len = ctypes.c_uint(ctypes.sizeof(info))
    if ctypes.CDLL("libc.so.6").getsockopt(
        s.fileno(), SOL_IP, IPT_SO_GET_INFO,
        ctypes.byref(info), ctypes.byref(buf_len)
    ) != 0:
        raise OSError(ctypes.get_errno(), "getsockopt IPT_SO_GET_INFO failed")

print("Entries:", info.num_entries, "bytes:", info.size)
