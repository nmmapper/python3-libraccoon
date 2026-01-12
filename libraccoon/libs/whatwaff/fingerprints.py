from typing import Dict, List, TypedDict


class FingerprintRule(TypedDict):
    headers: List[str]
    body: List[str]
    header_weight: int
    body_weight: int


WAF_FINGERPRINTS: Dict[str, FingerprintRule] = {

    # =========================
    # Cloud & CDN WAFs
    # =========================
    "Cloudflare": {
        "headers": [
            r"cf-ray",
            r"cf-cache-status",
            r"server:\s*cloudflare",
            r"__cfduid",
        ],
        "body": [
            r"attention required",
            r"error\s*1020",
            r"cloudflare ray id",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    "AWS WAF": {
        "headers": [
            r"x-amz(n)?-requestid",
            r"x-amz-cf-id",
        ],
        "body": [
            r"blocked by aws",
            r"aws waf",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    "Akamai Kona Site Defender": {
        "headers": [
            r"x-akamai-edgescape",
            r"akamai",
        ],
        "body": [
            r"access denied",
            r"akamai ghost",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    "Fastly / Signal Sciences": {
        "headers": [
            r"x-fastly",
            r"x-sigsci",
        ],
        "body": [
            r"signal sciences",
            r"sigsci",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    "Imperva Incapsula": {
        "headers": [
            r"x-iinfo",
            r"incap_ses",
        ],
        "body": [
            r"incapsula",
            r"request blocked",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    # =========================
    # Appliance / Enterprise
    # =========================
    "F5 BIG-IP ASM": {
        "headers": [
            r"bigipserver",
            r"x-waf-protected",
        ],
        "body": [
            r"the requested url was rejected",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    "Fortinet FortiWeb": {
        "headers": [
            r"fortigate",
            r"fortiweb",
        ],
        "body": [
            r"fortiweb",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    "Barracuda WAF": {
        "headers": [
            r"barracuda",
        ],
        "body": [
            r"you have been blocked",
        ],
        "header_weight": 3,
        "body_weight": 1,
    },

    # =========================
    # Open Source / Software
    # =========================
    "ModSecurity": {
        "headers": [
            r"mod[_-]?security",
        ],
        "body": [
            r"mod[_-]?security",
        ],
        "header_weight": 2,
        "body_weight": 1,
    },

    "NAXSI": {
        "headers": [
            r"naxsi",
        ],
        "body": [
            r"naxsi denied",
        ],
        "header_weight": 2,
        "body_weight": 1,
    },
}
