__author__ = 'Administrator'
import dpkt
import pcap
import socket
import datetime
import platform


if platform.system() == "Windows":
    SYS_INFO = 0
elif platform.system() == "Linux":
    SYS_INFO = 1

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    if SYS_INFO == 0:
        return socket.inet_ntoa(address)
    return socket.inet_ntop(socket.AF_INET, address)

def print_packets(p):
    for ts,pkt in p:
        print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts))
        eth = dpkt.ethernet.Ethernet(pkt)
        print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            continue
            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        tcp = ip.data
        print `tcp.data`
        # Print out the info
        print 'IP: %s:%d -> %s:%d  (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % (ip_to_str(ip.src),tcp.sport,ip_to_str(ip.dst),tcp.dport,ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)

def test():
    winPcap = pcap.pcap()
    #winPcap.setfilter("tcp port 80")
    print_packets(winPcap)

def readPcap():
    """Open up a test pcap file and print out the packets"""
    with open('e:\\cron.cap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)

if __name__ == '__main__':
    test()
    #readPcap()