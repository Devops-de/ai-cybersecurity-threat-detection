from typing import Dict, Any, List

class ThreatIntelligenceService:
    """
    Threat Intelligence and IOC Enrichment Engine.
    Provides reputation scores, GeoIP attribution, ASN data, and MITRE mapping.
    """
    def __init__(self):
        self.known_reputations = {
            "185.220.101.5": {
                "ip": "185.220.101.5",
                "country": "Germany",
                "city": "Frankfurt",
                "asn": "AS205100 (Tor Exit Node)",
                "reputation_score": 98,
                "category": "Tor Anonymizer / Port Scanner",
                "associated_threat_actor": "Unattributed / Reconnaissance Botnet"
            },
            "198.51.100.42": {
                "ip": "198.51.100.42",
                "country": "Russian Federation",
                "city": "Moscow",
                "asn": "AS49447 (Bulletproof Hosting)",
                "reputation_score": 95,
                "category": "C2 Infrastructure",
                "associated_threat_actor": "APT29 / Cozy Bear"
            },
            "45.33.32.156": {
                "ip": "45.33.32.156",
                "country": "United States",
                "city": "Fremont",
                "asn": "AS63949 (Linode LLC)",
                "reputation_score": 78,
                "category": "Data Drop / Exfiltration Staging",
                "associated_threat_actor": "FIN7 Affiliate"
            },
            "203.0.113.88": {
                "ip": "203.0.113.88",
                "country": "China",
                "city": "Shanghai",
                "asn": "AS4134 (Chinanet)",
                "reputation_score": 85,
                "category": "Exploit Scanner",
                "associated_threat_actor": "Volt Typhoon Suspect"
            }
        }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Returns threat intelligence metadata for any IP address."""
        if ip in self.known_reputations:
            return self.known_reputations[ip]
        
        # Default enterprise or external classification
        if ip.startswith(("10.", "192.168.", "172.16.")):
            return {
                "ip": ip,
                "country": "Internal Enterprise",
                "city": "HQ Datacenter",
                "asn": "Private RFC1918",
                "reputation_score": 0,
                "category": "Trusted Corporate Asset",
                "associated_threat_actor": "None"
            }
        else:
            return {
                "ip": ip,
                "country": "United States",
                "city": "Ashburn",
                "asn": "AS15169 (Public Transit)",
                "reputation_score": 15,
                "category": "Unclassified Public IP",
                "associated_threat_actor": "None"
            }

    def get_global_threat_feed(self) -> List[Dict[str, Any]]:
        """Returns active threat telemetry across international indicators."""
        return list(self.known_reputations.values())
