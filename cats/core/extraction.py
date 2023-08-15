#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import xml.etree.ElementTree
from typing import Any


def nmap_nw_extract(path: str) -> list[dict[str, list[Any]]]:
    """Get scan results from nmap scan result output (XML file)

    Read nmap XML format scan result file (-oX) and get scan result information.
    See https://nmap.org/book/nmap-dtd.html for the format of nmap's XML output.

    returns list[ host_info ]

    host_info[addresses] = list[ (ipaddr, addrtype) ];  addrtype ::= 'ipv4'|'ipv6'|'mac'
    host_info[hostnames] = list[ hostname ]
    host_info[ports] = list[ (proto, portid, service, product, version) ]; proto ::= 'ip'|'tcp'|'udp'|'sctp'
    host_info[oss] = list[ (osname, accuracy) ]


    Parameters
    ----------
    path : str
        nmap scan result file path

    Returns
    -------
    list[dict[str, list[Any]]]
        scan result info
    """
    results = []
    root_elem = xml.etree.ElementTree.parse(path).getroot()

    for host_elem in root_elem.findall("./host"):
        host_info = dict()

        # addresses
        addresses = list()
        host_info["addresses"] = addresses
        for addr_elem in host_elem.findall("./address"):
            addr_value = addr_elem.attrib["addr"]
            addr_type = addr_elem.attrib.get("addrtype", "ipv4")
            addresses.append((addr_value, addr_type))

        # hostnames
        hostnames = list()
        host_info["hostnames"] = hostnames
        for hostname_elem in host_elem.findall("./hostnames/hostname"):
            hostnames.append(hostname_elem.attrib["name"])

        # ports
        ports = list()
        host_info["ports"] = ports
        for port_elem in host_elem.findall("./ports/port"):
            state_elem = port_elem.find("./state")
            if state_elem.attrib["state"] != "open":
                continue

            portid = int(port_elem.attrib["portid"])
            proto = port_elem.attrib["protocol"]

            service_name, product, version = None, None, None
            service_elem = port_elem.find("./service")
            if service_elem is not None:
                service_name = service_elem.attrib["name"]
                product = service_elem.attrib.get("product", None)
                version = service_elem.attrib.get("version", None)

            ports.append((proto, portid, service_name, product, version))

        # os
        oss = list()
        host_info["oss"] = oss
        for osmatch_elem in host_elem.findall("./os/osmatch"):
            osname = osmatch_elem.attrib["name"]
            accuracy = osmatch_elem.attrib["accuracy"]
            oss.append((osname, accuracy))

        results.append(host_info)

    return results
