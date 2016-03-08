#!/usr/bin/env python
"""
	Given an IPv6 address or IPv6 network prefix, it shows all information
        about assignable addresses and address formats.
"""

import ipaddr #require external library
import argparse
import re
#from termcolor import colored

def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.RawDescriptionHelpFormatter,
        description = __doc__+("""
        Examples:\n
           Provide all informations about a single IPv6 address.
             # ip6calc.py 2001:41d0:8:17d8::1


           Provide all informations about an IPv6 network prefix and all
           contained addresses:
             # ip6calc.py 2001:41d0:8:17d8::1/64

           Addresses can be provided in binary form too:
             # ip6calc.py 0010000000000001:0100000111010000:"""
"""0000000000001000:0001011111011000:0000000000000000:0000000000000000:"""
"""0000000000000000:0000000000000001

             # ip6calc.py 0010000000000001:0100000111010000:"""
"""0000000000001000:0001011111011000:0000000000000000:0000000000000000:"""
"""0000000000000000:0000000000000001/64

    """))

    parser.add_argument("ip6addr", 
        help = ("IPv6 address or network prefix (compressed, exploded IPv6"
                " format or full binary format)"))

    parser.add_argument("--print-all-subnets-counts",
        help = ("When given a network prefix, it forces to compute the "
                "number of subnets available for each subnet size"),
        action="store_true")

    parser.add_argument("--show-deaggregated-into",
        help = ("When given a network prefix, it shows all the IPv6 "
               "sub-prefixes of length N contained in the prefix provided"),
               type = int)


    return parser.parse_args()

def get_binary_address(addr):
    bin_str = bin(int(addr)).replace("0b","").zfill(128)
    return "{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}".format(
        bin_str[0:16],
        bin_str[16:32],
        bin_str[32:48],
        bin_str[48:64],
        bin_str[64:80],
        bin_str[80:96],
        bin_str[96:112],
        bin_str[112:128],
    )

def address_reprs(addr_obj):
    prefixlen_str = ""
    if (type(addr_obj) == ipaddr.IPv6Network) and (addr_obj.prefixlen < 128):
        prefixlen_str = "/{0}".format(addr_obj.prefixlen)
    return ("  (Compressed)  {compr}\n"
            "    (Exploded)  {extend}\n"
            "      (Binary)  {binary}{prefix}\n".format(
                compr = str(addr_obj),
                extend = addr_obj.exploded,
                binary = get_binary_address(addr_obj),
                prefix = prefixlen_str,
            )
           )

def address_type_str(addr):
    if addr.is_link_local:
        return "link local"
    elif addr.is_loopback:
        return "loopback"
    elif addr.is_multicast:
        return "multicast"
    elif addr.is_private:
        return "private"
    elif addr.is_reserved:
        return "reserved"
    elif addr.is_site_local:
        return "site local"
    elif addr.is_unspecified:
        return "unspecified"
    else:
        return "global unicast"

def convert_from_binary(addr):
    # Note that the binary address my contain or not contain any separator
    # between groups.
    token = addr.split("/")
    bin_match = re.match("([01]{16})[^01]*([01]{16})[^01]*([01]{16})[^01]*"
                         "([01]{16})[^01]*([01]{16})[^01]*([01]{16})[^01]*"
                         "([01]{16})[^01]*([01]{16})", token[0])
    output_addr = ""
    for group in bin_match.groups():
        output_addr += hex(int(group, 2))[2:].zfill(4) + ":"
    # Remove final column
    return (output_addr[:-1] + "/" + token[1])

def print_available_subnets_of_prefix(addr_obj, n):
    print("   * {num} (2^{exp} or {num:.2g}) subnets /{length}".format(       
          num = 2**(n-addr_obj.prefixlen),                            
          exp = (n-addr_obj.prefixlen),
          length = n))

def print_addr_info(addr, show_all_subnet_sizes, deaggregate_to = False):
    is_network = False

    # Convert the address if provided in binary form
    if len(addr) >= 128 and \
       re.match("([01]{16}[^01]*){7}[01]{16}(/[0-9]+)?", addr):
        addr = convert_from_binary(addr)
    if ("/" in addr) and (int(addr.split("/")[-1]) != 128):
        is_network = True
        addr_obj = ipaddr.IPNetwork(addr)
    else:
        addr_obj = ipaddr.IPAddress(addr.split("/")[0])

    if addr_obj.version != 6: return

    print("Address:")
    print(address_reprs(addr_obj))

    print("Address type is: {addrtype}\n".format(
        addrtype = address_type_str(addr_obj)))

    if is_network:
        reserved_addresses = 0
        print("Netmask:")
        print(address_reprs(addr_obj.netmask))

        print("First address assignable: ")
        print(address_reprs(addr_obj[0]))

        print("Last address assignable: ")
        print(address_reprs(addr_obj[-1]))       

        print("Total number of addresses: {num} (2^{exp} or {num:.2g})"
              "\n".format(num = addr_obj.numhosts,
                          exp = 128-addr_obj.prefixlen))
        print("\n")

        if (addr_obj.prefixlen <= 126):
            reserved_addresses += 1
            print("First address assignable (excluding "
                  "\"subnet-router anycast\" of RFC 2526):")
            print(address_reprs(addr_obj[0] + 1))

        if (addr_obj.prefixlen >= 64) and (addr_obj.prefixlen <= 128-8):
            reserved_addresses += 128
            print("Last address assignable (Excluding \"reserved\" addresses "
                  "of RFC 2526): ")
            print(address_reprs(addr_obj[-129]))

        if reserved_addresses > 0:
            print("Total number of addresses (Excluding \"reserved\" "
                  "addresses): {num} ({num:.2g})\n".format(
                  num = addr_obj.numhosts-reserved_addresses))

        if show_all_subnet_sizes:
            print("\nThis prefix can contain one of the following:")
            for n in range(addr_obj.prefixlen + 1, 128)[::-1]:
                print_available_subnets_of_prefix(addr_obj, n)
        else:
            if addr_obj.prefixlen < 64:
                print("\nThis prefix can contain one of the following:")
                print_available_subnets_of_prefix(addr_obj, 64)
            if addr_obj.prefixlen < 56:
                print_available_subnets_of_prefix(addr_obj, 56)
            if addr_obj.prefixlen < 48:
                print_available_subnets_of_prefix(addr_obj, 48)
            if addr_obj.prefixlen < 32:
                print_available_subnets_of_prefix(addr_obj, 32)

        if deaggregate_to and deaggregate_to > addr_obj.prefixlen:
            print("\nList of /{deag_len} prefixes deaggregated from the "
                  "{orig_len} provided:".format(deag_len = deaggregate_to,
                  orig_len = addr_obj.prefixlen))
            for p in addr_obj.Subnet(deaggregate_to - addr_obj.prefixlen):
                print(p.exploded)
            

if __name__ == "__main__":
    args = parse_args()
    if args.show_deaggregated_into:
        print_addr_info(args.ip6addr, args.print_all_subnets_counts,
                        args.show_deaggregated_into)
    else:
        print_addr_info(args.ip6addr, args.print_all_subnets_counts)

