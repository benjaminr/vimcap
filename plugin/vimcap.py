import argparse
import os
import sys
import unicodedata
import scapy
from scapy.all import Packet, wrpcap, rdpcap
from scapy.utils import linehexdump
from binascii import unhexlify


def load_pcap(pcap: str):
    """
    Load a pcap and dump packet hex to stdout for vim

    Arguments:
        pcap {str} -- path to pcap
    """

    for p in rdpcap(pcap):
        linehexdump(p, onlyhex=1)


def write_pcap(pcap: str):
    """
    Converts vim buffer contents from hex to bytes and
    writes to a pcap

    Arguments:
        pcap {str} -- path to pcap
    """
    try:
        for line in sys.stdin:
            data_line = line.rstrip()
            data_bytes = unhexlify(data_line.replace(" ", ""))
            wrpcap(pcap + ".tmp", data_bytes, append=True)
            print(data_line)
        os.replace(pcap + ".tmp", pcap)
    except Exception as e:
        print(e)


def hex_to_ascii():
    """
    Converts vim buffer contents from hex to ascii and 
    writes to stdout for consumption into a new buffer
    """
    try:
        printable = {
            "Lu",
            "Ll",
            "Pc",
            "Pd",
            "Pe",
            "Pf",
            "Pi",
            "Po",
            "Ps",
            "Sc",
            "Sm",
            "Nd",
        }
        for line in sys.stdin:
            data_line = line.rstrip()
            data_bytes = unhexlify(data_line.replace(" ", ""))
            filtered_string = "  ".join(
                c if (unicodedata.category(c) in printable) else "."
                for c in data_bytes.decode("utf-8", errors="replace")
            )
            print(filtered_string)
    except Exception as e:
        print(e)


def hex_to_uni():
    """
    Converts vim buffer contents from hex to unicode and
    writes to stdout for consumption into a new buffer
    """
    try:
        for line in sys.stdin:
            data_line = line.rstrip()
            data_bytes = unhexlify(data_line.replace(" ", ""))
            filtered_string = data_bytes.decode("utf-8", errors="replace")
            print(filtered_string)
    except Exception as e:
        print(e)


def scapy_print(encap: str):
    """
    Converts vim buffer contents from hex to bytes and
    encapsulates the payload in the Scapy encapsulation
    protocol specified.

    Writes a single line summary of protocol dissection to
    stdout for consumption into a new buffer.

    Arguments:
        encap {str} -- Scapy encapsulating protocol
    """
    try:
        parent = getattr(scapy.all, encap)
        if not issubclass(parent, Packet):
            print(f"{encap} is an unknown protocol.")
        for line in sys.stdin:
            data_line = line.rstrip()
            data_bytes = unhexlify(data_line.replace(" ", ""))
            p = Packet() / parent(data_bytes)
            print(p.summary())
    except Exception as e:
        print(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--load", nargs="?")
    parser.add_argument("-w", "--write", nargs="?")
    parser.add_argument("-a", "--ascii", action="store_true")
    parser.add_argument("-u", "--uni", action="store_true")
    parser.add_argument("-p", "--print-packet", nargs="?")
    args = parser.parse_args()

    if args.load:
        load_pcap(args.load)
    if args.write:
        write_pcap(args.write)
    if args.ascii:
        hex_to_ascii()
    if args.uni:
        hex_to_uni()
    if args.print_packet:
        scapy_print(args.print_packet)
