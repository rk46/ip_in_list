#!/usr/bin/env python

"""Checks if an IPv4 address is in a list of IPv4 addresses. 

The list of IP addresses may contain a combination of single IP addresses
and ranges of IP addresses. Ranges of IP addresses may be expressed in CIDR
notation or as two IP addresses separated by a hyphen. 

    Typical usage example:

    ip_in_list.py 10.0.0.15 10.0.0.0/24
    ip_in_list.py 10.0.0.15 "10.0.0.1, 10.0.0.5-10.0.0.23"
    ip_in_list.py 10.0.0.15 -f ip_list.txt
"""
import sys
import argparse
import ipaddress

def convert_ip(ip):
    """Converts IP addresses from a string to ipaddress ip_address Python objects.

    Takes in either a single IP address, or a range of IP addresses expressed as 
    two IP addresses separated by a hyphen. 
    
    Args:
        ip (str): IP address or IP address range to convert.

    Returns:
        converted (List[ipaddress.ip_address]): Converted ip_address objects in a list.
    """

    converted = []

    # For IP address ranges, convert to int representation for easier calculation
    if '-' in ip:
        first_ip, last_ip = ip.split('-')
        try:
            ip_int = int(ipaddress.ip_address(first_ip))
            last_ip_int = int(ipaddress.ip_address(last_ip))

            if ip_int >= last_ip_int:
                raise ValueError(f'Warning: {ip} is not a valid IP address range')

            while(ip_int <= last_ip_int):
                converted.append(ipaddress.ip_address(ip_int))
                ip_int += 1

        except:
            raise ValueError(f'Warning: {ip} is not a valid IP address range')
    else:
        try:
            ip_object = ipaddress.ip_address(ip)
            converted.append(ip_object)
        except:
            raise ValueError(f'Warning: {ip} is not a valid IP address')

    return converted

def convert_ip_cidr(ip):
    """Converts IP addresses expressed in CIDR to an ipaddress IPv4Network Python object.

    Args:
        ip (str): IP addresses to convert.

    Returns:
        converted (ipaddress.IPv4Network): Converted IPv4Network object.    

    """

    try:
        converted = ipaddress.IPv4Network(ip)
    except:
        raise ValueError(f'Warning: {ip} is not in valid CIDR notation')

    return converted 

def ip_in_list(ip_to_check, addresses, delimiter=','):
    """Checks if an IPv4 address is in a list of IPv4 addresses.

    The list of IP addresses may contain a combination of single IP addresses
    and ranges of IP addresses separated by a delimiter. Ranges may be expressed
    in CIDR notation or two IP addresses separated by a hyphen.

    Args:
        ip_to_check (str): The IP address to check.
        addresses (str): The list of IP addresses to check in. 
        delimiter (str): The delimiter between IP addresses in list_of_addresses.

    Returns:
        bool: The return value. True means the IP address is in the list. 
    """

    try:
        ip_to_check_converted = ipaddress.ip_address(ip_to_check)
    except:
        print(f'{ip_to_check} is not a valid IPv4 address')
        sys.exit(1)

    list_of_ranges = [item.strip() for item in addresses.split(delimiter)]

    for item in list_of_ranges:
        if '/' in item:
            try:
                network = convert_ip_cidr(item)
                if ip_to_check_converted in network:
                    return True, item  
            except Exception as e:
                print(e)
                pass
        else:
            try:
                ip_object_list = convert_ip(item)
                if ip_to_check_converted in ip_object_list:
                    return True, item
            except Exception as e:
                print(e)
                pass        

    return False, None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_to_check', help='IPv4 address to check')
    parser.add_argument('-d', '--delimiter', default=',')

    # Arguments must contain either contain the list itself, or filename containing the list
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('list_of_addresses', nargs='?', help='List of IP addresses')
    group.add_argument('-f', '--filename', help = 'File containing list of IP addresses')

    args = parser.parse_args()     

    ip_to_check = args.ip_to_check
    
    # Determine whether a list was passed in, or the filename containing the list
    if args.filename:
        try:
            with open(args.filename) as f:
                list_of_addresses = f.read()
        except:
            print(f'Unable to open file {args.filename}')
            sys.exit(1) 
    else:
        list_of_addresses = args.list_of_addresses

    # Argument parsing completed, call function that will perform the check
    result, entry = ip_in_list(ip_to_check, list_of_addresses, args.delimiter)

    # Print the results
    if result == True:
        print(f'Found: {args.ip_to_check} is in entry "{entry}".')
    else:
        print(f'Not found: {args.ip_to_check} is not in the list provided.')

if __name__ == '__main__':
    main()


