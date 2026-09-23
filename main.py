import base64
import json
import os
import re
import socket
import urllib.parse
import geoip2.database
import requests

TARGET_COUNTRIES = ["NO", "IS", "UA", "DE", "NL"]
SOURCE_URL = "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt"
MMDB_PATH = "GeoLite2-Country.mmdb"


def parse_host(uri: str) -> str | None:
    try:
        uri = uri.strip()
        if not uri:
            return None

        if uri.startswith("vmess://"):
            b64_part = uri[8:].split("#")[0]
            b64_part += "=" * (-len(b64_part) 