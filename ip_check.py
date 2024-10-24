import csv
from dataclasses import dataclass
from os import getenv
from typing import Optional

from dotenv import load_dotenv

import grequests
import requests
import click

load_dotenv()

TOKEN = getenv("TOKEN", "")


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


def get_url(ip_addr: str = None) -> str:
    token_part = ""
    if TOKEN:
        token_part = f"?token={TOKEN}"

    if ip_addr is None:
        url = f'https://ipinfo.io/json{token_part}'
    else:
        url = f'https://ipinfo.io/{ip_addr}/json{token_part}'
    return url


def get_ip_info(ip_addr: str = None) -> IPInformation:
    """
    Returns information about the
    :param ip_addr:
    :return:
    """
    url = get_url(ip_addr)
    response = requests.get(url)
    ip_info = IPInformation(**response.json())
    return ip_info


def get_ip_info_async(urls: list[str]):
    rs = (grequests.get(u) for u in urls)
    responses = grequests.map(rs, size=10)
    results = []
    for ip in responses:
        results.append(IPInformation(**ip.json()))
    return results


def write_csv_file(responses: list[IPInformation], outfile: str):
    header = ["ip", "country", "city", "loc", "org", "postal", "region", "timezone", "hostname", "readme"]
    with open(outfile, "w", newline="") as f:
        writer = csv.DictWriter(f, dialect="excel", fieldnames=header)
        writer.writeheader()
        for info in responses:
            writer.writerow(info.__dict__)

@click.command()
@click.argument("logfile")
@click.argument("csv_filename")
def get_info(logfile: str, csv_filename: str):
    ip_set = extract_ip_from_log(logfile)
    urls = [get_url(ip) for ip in ip_set]
    whois_responses = get_ip_info_async(urls)

    write_csv_file(whois_responses, outfile=csv_filename)


get_info()