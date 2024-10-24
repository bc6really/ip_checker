import os
from dataclasses import dataclass
from pprint import pprint
from typing import Optional

from dotenv import load_dotenv

import requests

load_dotenv()


def extract_ip_from_log(log_file) -> set:
    ip_addresses = set()
    with open(log_file, 'r') as f:
        for line in f:
            parts = line.split(" - ", 2)

            ip_addresses.add(parts[0])
    return ip_addresses


@dataclass
class IPInformation:
    city: str
    country: str
    ip: str
    loc: str
    org: str
    postal: str
    region: str
    timezone: str
    hostname: Optional[str] = ""
    readme: Optional[str] = ""


def get_ip_info(ip_addr: str = None) -> IPInformation:
    """
    Returns information about the
    :param ip_addr:
    :return:
    """
    token = os.getenv('TOKEN', '')
    token_part = ""
    if token:
        token_part = f"?token={token}"

    if ip_addr is None:
        url = f'https://ipinfo.io/json{token_part}'
    else:
        url = f'https://ipinfo.io/{ip_addr}/json{token_part}'
    response = requests.get(url)
    ip_info = IPInformation(**response.json())
    print(f"{ip_info.ip},{ip_info.country}")
    # print(f"{ip_addr},{response.country}")

    return ip_info


if __name__ == "__main__":
    # info = get_ip_info()
    # print(info)
    ip_set = extract_ip_from_log('web-server access logs filtered donations.txt')
    whois_responses = [get_ip_info(ip) for ip in ip_set]
    print(20 * "=")
    for i in whois_responses:
        print(f"{i.ip},{i.country}")
    print(len(ip_set))
