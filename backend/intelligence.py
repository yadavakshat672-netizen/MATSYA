"""MATSYA Cyber Intelligence Platform: DNS, RDAP, GeoIP, reputation and graph."""

import ipaddress
import os
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    dns = None
    DNS_AVAILABLE = False

try:
    import maxminddb
except ImportError:
    maxminddb = None


router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence"])
TIMEOUT = 8
BASE_DIR = Path(__file__).resolve().parent

# Default database location:
# backend/data/GeoLite2-City.mmdb
# You may override it with the GEOIP_DB_PATH environment variable.
GEOIP_DB_PATH = Path(
    os.getenv(
        "GEOIP_DB_PATH",
        str(BASE_DIR / "data" / "GeoLite2-City.mmdb"),
    )
).expanduser()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
USER_AGENT = "MATSYA-Cyber-Intelligence/1.0"


def valid_domain(value: str) -> str:
    """Normalize and validate a fully qualified domain name."""
    value = str(value).strip().rstrip(".").lower()
    if (
        not value
        or len(value) > 253
        or "://" in value
        or "/" in value
        or ":" in value
    ):
        raise ValueError("Enter a valid domain name, not a URL or IP address.")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Expected a domain name, not an IP address.")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain.") from exc

    labels = value.split(".")
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or not label_pattern.fullmatch(label)
        for label in labels
    ):
        raise ValueError("Invalid fully qualified domain name.")

    return value


def public_ip(value: str):
    """Return an IP address only if it is globally routable."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError("Invalid IP address.") from exc

    if not address.is_global:
        raise ValueError("Only globally routable public IP addresses are supported.")

    return address


def http_json(url: str, headers=None, params=None):
    """Make a bounded HTTP GET and return JSON plus an optional error."""
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/rdap+json, application/json",
        **(headers or {}),
    }

    try:
        response = requests.get(
            url,
            headers=request_headers,
            params=params,
            timeout=TIMEOUT,
        )
        if response.status_code == 404:
            return None, "No record found"
        response.raise_for_status()
        return response.json(), None
    except requests.RequestException as exc:
        return None, f"Request failed: {exc}"
    except ValueError:
        return None, "Provider returned invalid JSON"


def rdap_lookup(kind: str, value: str) -> dict:
    """Look up registration information through the public RDAP aggregator."""
    if kind not in {"domain", "ip"}:
        return {"status": "unavailable", "reason": "Unsupported RDAP lookup type."}

    data, error = http_json(f"https://rdap.org/{kind}/{value}")
    if not data:
        return {
            "status": "unavailable",
            "reason": error or "No RDAP record found",
        }

    return {
        "status": "available",
        "source": "RDAP",
        "handle": data.get("handle"),
        "name": data.get("name"),
        "status_codes": data.get("status", []),
        "events": [
            {
                "action": event.get("eventAction"),
                "date": event.get("eventDate"),
            }
            for event in data.get("events", [])
        ],
    }


def dns_lookup(domain: str) -> dict:
    """Query common DNS record types."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    records, errors = {}, {}

    if not DNS_AVAILABLE:
        return {
            "status": "unavailable",
            "reason": "Install dnspython to query DNS records.",
            "records": {},
            "resolved_ips": [],
        }

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=TIMEOUT,
            )
            if record_type == "MX":
                records[record_type] = [
                    {
                        "priority": item.preference,
                        "host": str(item.exchange).rstrip("."),
                    }
                    for item in answers
                ]
            elif record_type == "TXT":
                records[record_type] = [
                    b"".join(item.strings).decode("utf-8", errors="replace")
                    for item in answers
                ]
            else:
                records[record_type] = [
                    str(item).rstrip(".")
                    if record_type in {"NS", "CNAME"}
                    else str(item)
                    for item in answers
                ]
        except Exception as exc:
            errors[record_type] = str(exc)

    addresses = sorted(set(records.get("A", []) + records.get("AAAA", [])))
    return {
        "status": "available" if records else "unavailable",
        "records": records,
        "resolved_ips": addresses,
        "errors": errors,
    }


def resolve_domain_ips(domain: str) -> list:
    """Resolve domain addresses, falling back to the system resolver."""
    result = dns_lookup(domain)
    found = set(result.get("resolved_ips", []))

    if not found:
        try:
            for item in socket.getaddrinfo(
                domain,
                None,
                type=socket.SOCK_STREAM,
            ):
                try:
                    found.add(str(ipaddress.ip_address(item[4][0])))
                except ValueError:
                    pass
        except socket.gaierror:
            pass

    return sorted(found)


def geoip_lookup(address) -> dict:
    """
    Look up approximate IP geolocation using the local GeoLite2 City database.

    The default database path is backend/data/GeoLite2-City.mmdb, relative to
    this file. Set GEOIP_DB_PATH if your database is stored elsewhere.
    """
    try:
        address = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return {"status": "unavailable", "reason": "Invalid IP address."}

    if not address.is_global:
        return {
            "status": "unavailable",
            "reason": "GeoIP lookup requires a public IP address.",
        }

    if maxminddb is None:
        return {
            "status": "unavailable",
            "reason": "Install maxminddb to read a GeoLite2 database.",
        }

    if not GEOIP_DB_PATH.is_file():
        return {
            "status": "unavailable",
            "reason": f"GeoLite2 database not found: {GEOIP_DB_PATH}",
        }

    try:
        with maxminddb.open_database(str(GEOIP_DB_PATH)) as reader:
            result = reader.get(str(address))

        if not result:
            return {
                "status": "unavailable",
                "reason": "No GeoIP record for this IP address.",
            }

        country = result.get("country") or {}
        registered_country = result.get("registered_country") or {}
        subdivisions = result.get("subdivisions") or []
        subdivision = subdivisions[0] if subdivisions else {}
        city = result.get("city") or {}
        location = result.get("location") or {}

        latitude = location.get("latitude")
        longitude = location.get("longitude")

        return {
            "status": "available",
            "source": "MaxMind GeoLite2 City",
            "country": (country.get("names") or {}).get("en"),
            "country_iso_code": country.get("iso_code"),
            "registered_country": (registered_country.get("names") or {}).get("en"),
            "region": (subdivision.get("names") or {}).get("en"),
            "city": (city.get("names") or {}).get("en"),
            "latitude": latitude,
            "longitude": longitude,
            "has_coordinates": (
                isinstance(latitude, (int, float))
                and isinstance(longitude, (int, float))
            ),
            "accuracy_radius_km": location.get("accuracy_radius"),
            "time_zone": location.get("time_zone"),
            "note": (
                "Approximate IP geolocation; it does not identify a person's "
                "exact location."
            ),
        }
    except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
        return {"status": "unavailable", "reason": f"GeoIP lookup failed: {exc}"}
    except Exception as exc:
        return {"status": "unavailable", "reason": f"GeoIP lookup failed: {exc}"}


def abuseipdb_lookup(address) -> dict:
    """Check IP reputation if an AbuseIPDB API key is configured."""
    if not ABUSEIPDB_API_KEY:
        return {
            "status": "unavailable",
            "source": "AbuseIPDB",
            "reason": "ABUSEIPDB_API_KEY is not configured.",
        }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            params={"ipAddress": str(address), "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "status": "available",
            "source": "AbuseIPDB",
            "ip_address": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "status": "unavailable",
            "source": "AbuseIPDB",
            "reason": str(exc),
        }


def virustotal_lookup(kind: str, value: str) -> dict:
    """Look up IP or domain reputation when a VirusTotal key is configured."""
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "unavailable",
            "source": "VirusTotal",
            "reason": "VIRUSTOTAL_API_KEY is not configured.",
        }

    if kind not in {"domain", "ip"}:
        return {
            "status": "unavailable",
            "source": "VirusTotal",
            "reason": "Unsupported lookup type.",
        }

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/{kind}s/{value}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY,
                "User-Agent": USER_AGENT,
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        return {
            "status": "available",
            "source": "VirusTotal",
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
    except (requests.RequestException, ValueError) as exc:
        return {
            "status": "unavailable",
            "source": "VirusTotal",
            "reason": str(exc),
        }


@router.get("/domain/{domain}")
def domain_intelligence(domain: str):
    """Return DNS, RDAP, GeoIP and reputation information for a domain."""
    try:
        domain = valid_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    dns_result = dns_lookup(domain)
    addresses = dns_result.get("resolved_ips", []) or resolve_domain_ips(domain)
    ip_results = []

    for address in addresses[:20]:
        try:
            ip = public_ip(address)
        except ValueError:
            continue

        ip_results.append(
            {
                "query": str(ip),
                "rdap": rdap_lookup("ip", str(ip)),
                "geoip": geoip_lookup(ip),
                "reputation": abuseipdb_lookup(ip),
                "virustotal": virustotal_lookup("ip", str(ip)),
            }
        )

    return {
        "query": domain,
        "rdap": rdap_lookup("domain", domain),
        "dns": dns_result,
        "resolved_ips": addresses,
        "ip_intelligence": ip_results,
        "reputation": virustotal_lookup("domain", domain),
        "limitations": [
            "IP geolocation is approximate and does not identify a person's exact location.",
            "DNS, RDAP and GeoIP alone do not establish that a domain is malicious.",
            "Cloud, CDN and tracking domains may resolve to shared infrastructure.",
            "Reputation results depend on provider access and configured API keys.",
        ],
    }


@router.get("/ip/{address}")
def ip_intelligence(address: str):
    """Return RDAP, GeoIP and reputation information for a public IP."""
    try:
        ip = public_ip(address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "query": str(ip),
        "rdap": rdap_lookup("ip", str(ip)),
        "geoip": geoip_lookup(ip),
        "reputation": abuseipdb_lookup(ip),
        "virustotal": virustotal_lookup("ip", str(ip)),
    }


class GraphRequest(BaseModel):
    report: dict = Field(default_factory=dict)


@router.post("/graph")
def relationship_graph(body: GraphRequest):
    """Build an association graph from indicators extracted from an email."""
    report = body.report or {}
    nodes, edges = {}, {}

    def add_node(node_id, kind, label):
        if node_id and node_id not in nodes:
            nodes[node_id] = {
                "id": str(node_id),
                "type": kind,
                "label": str(label)[:300],
            }

    def add_edge(source, target, relation):
        if source and target and source != target:
            edge_id = f"{source}|{target}|{relation}"
            edges[edge_id] = {
                "id": edge_id,
                "source": str(source),
                "target": str(target),
                "label": relation,
                "evidence": "Extracted from uploaded email",
            }

    sender = report.get("sender")
    recipient = report.get("recipient")
    add_node(sender, "email", sender)
    add_node(recipient, "email", recipient)

    if sender and recipient:
        add_edge(sender, recipient, "email header association")

    domains = set(report.get("domains") or [])
    urls = set(report.get("urls") or [])
    ips = set(report.get("ips") or [])

    for url in urls:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue

        add_node(url, "url", url)
        add_edge(sender, url, "email contains URL")

        if host in domains:
            add_node(host, "domain", host)
            add_edge(url, host, "URL hostname")

        if host in ips:
            add_node(host, "ip", host)
            add_edge(url, host, "URL hostname")

    for domain in domains:
        add_node(domain, "domain", domain)
        if sender:
            add_edge(sender, domain, "domain extracted from email")

    for address in ips:
        add_node(address, "ip", address)

    return {
        "status": "available",
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "limitations": [
            "Relationships are extracted associations, not proof of malicious activity.",
            "IP-to-domain DNS relationships are not inferred automatically.",
            "GeoIP and reputation are best-effort provider lookups and may be unavailable.",
        ],
    }
