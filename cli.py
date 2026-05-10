#!/usr/bin/env python3
"""
CIBERSEC TOOLS - Colección de herramientas profesionales y rápidas para ciberseguridad
Basado en las APIs públicas del archivo herramientas_ciberseguridad.txt

Uso:
    python cli.py <comando> [opciones]

Comandos disponibles:
    intel     - Inteligencia de amenazas y OSINT
    malware   - Análisis de malware
    vuln      - Evaluación de vulnerabilidades
    network   - Seguridad de red y reputación de IP
    web       - Seguridad de aplicaciones web
    auth      - Autenticación y seguridad de cuentas
    crypto    - Criptografía y cifrado
    fraud     - Detección de fraude
    dev       - Herramientas para desarrolladores
    legal     - Recursos para investigación y ley

Cada comando tiene sub-comandos para las APIs específicas de su categoría.
"""

import argparse
import sys
import os
import requests
import json
from typing import Dict, Any, Optional

# Configuración básica
USER_AGENT = "CIBERSEC-TOOLS/1.0"
TIMEOUT = 10

def make_request(url: str, method: str = "GET", headers: Optional[Dict] = None,
                 params: Optional[Dict] = None, data: Optional[Dict] = None,
                 api_key: Optional[str] = None, key_header: str = "X-API-Key") -> Dict[str, Any]:
    """Realiza una petición HTTP con manejo básico de errores."""
    if headers is None:
        headers = {}
    headers.setdefault("User-Agent", USER_AGENT)

    if api_key:
        headers[key_header] = api_key

    try:
        response = requests.request(
            method, url, headers=headers, params=params,
            json=data, timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json() if response.content else {}
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "status_code": getattr(e.response, 'status_code', None)}
    except json.JSONDecodeError:
        return {"error": "Respuesta no es JSON válido", "text": response.text[:200]}

# ==================== INTELIGENCIA DE AMENAZAS Y OSINT ====================

def shodan_search(query: str, api_key: str) -> Dict[str, Any]:
    """Busca en Shodan."""
    url = f"https://api.shodan.io/shodan/host/search"
    params = {"key": api_key, "query": query}
    return make_request(url, params=params)

def censys_search(query: str, api_id: str, api_secret: str) -> Dict[str, Any]:
    """Busca en Censys (simplificado)."""
    url = f"https://search.censys.io/api/v2/hosts/search"
    headers = {"Accept": "application/json"}
    data = {"q": query, "per_page": 10}
    # En realidad requiere autenticación básica más compleja
    return {"note": "Censys requiere autenticación básica compleja - implementar según documentación"}

def binary_edge_search(query: str, api_key: str) -> Dict[str, Any]:
    """Busca en BinaryEdge."""
    url = f"https://api.binaryedge.io/v2/query/{query}"
    headers = {"X-Key": api_key}
    return make_request(url, headers=headers)

def greynoise_query(ip: str, api_key: str) -> Dict[str, Any]:
    """Consulta IP en GreyNoise."""
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": api_key}
    return make_request(url, headers=headers)

def virustotal_scan(resource: str, api_key: str) -> Dict[str, Any]:
    """Escanea un recurso en VirusTotal."""
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": api_key, "resource": resource}
    return make_request(url, params=params)

# ==================== ANÁLISIS DE MALWARE ====================

def urlscan_scan(url_to_scan: str, api_key: str) -> Dict[str, Any]:
    """Envía URL para escaneo en URLScan.io."""
    url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    data = {"url": url_to_scan, "visibility": "public"}
    return make_request(url, method="POST", headers=headers, data=data)

def malwarebazaar_get_info(hash_value: str) -> Dict[str, Any]:
    """Obtiene información de un hash en MalwareBazaar."""
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": hash_value}
    return make_request(url, method="POST", data=data)

def virustotal_file_scan(file_path: str, api_key: str) -> Dict[str, Any]:
    """Sube un archivo para escaneo en VirusTotal (requiere archivo real)."""
    # Esta función sería más compleja - placeholder
    return {"note": "Para escaneo de archivos requiere multipart upload - ver documentación de VirusTotal"}

# ==================== EVALUACIÓN DE VULNERABILIDADES ====================

def nvd_search_cve(cve_id: str) -> Dict[str, Any]:
    """Busca información de una CVE en NVD (pública)."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    return make_request(url)

def vuldb_search(query: str, api_key: str) -> Dict[str, Any]:
    """Busca en VulDB."""
    url = "https://vuldb.com/?api"
    data = {"apikey": api_key, "search": query}
    return make_request(url, method="POST", data=data)

# ==================== SEGURIDAD DE RED ====================

def abuseipdb_check(ip: str, api_key: str) -> Dict[str, Any]:
    """Verifica reputación de IP en AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ip": ip, "maxAgeInDays": "90"}
    headers = {"Key": api_key, "Accept": "application/json"}
    return make_request(url, headers=headers, params=params)

def ip_reputation_check(ip: str) -> Dict[str, Any]:
    """Consulta IP en servicios gratuitos de reputación."""
    # Usando IPInfo como ejemplo (requiere token para uso extendido)
    url = f"https://ipinfo.io/{ip}/json"
    return make_request(url)

# ==================== SEGURIDAD WEB ====================

def google_safe_browsing_lookup(url_to_check: str, api_key: str) -> Dict[str, Any]:
    """Verifica URL con Google Safe Browsing."""
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    data = {
        "client": {"clientId": "cibersectools", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    return make_request(url, method="POST", data=data)

def urlscan_result(scan_id: str, api_key: str) -> Dict[str, Any]:
    """Obtiene resultados de un escaneo en URLScan.io."""
    url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    headers = {"API-Key": api_key}
    return make_request(url, headers=headers)

# ==================== AUTENTICACIÓN ====================

def haveibeenpwned_breach(account: str) -> Dict[str, Any]:
    """Verifica si una cuenta apareció en brechas (HIBP)."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
    headers = {"User-Agent": USER_AGENT}
    # Nota: HIBP requiere encabezado de usuario-agente y puede requerir clave de API para versiones pagas
    return make_request(url, headers=headers)

# ==================== CRIPTOGRAFÍA ====================

def hash_decrypt(hash_value: str, hash_type: str = "md5") -> Dict[str, Any]:
    """Intenta descifrar un hash usando servicios públicos (ejemplo con md5decrypt.net si tuviera API)."""
    # Placeholder - muchos servicios de cracking de hash no tienen API pública o requieren pago
    return {"note": "Descifrado de hashes: usar servicios como CrackStation, Hashes.org, o John the Ripper localmente"}

# ==================== DETECCIÓN DE FRAUDE ====================

def fraudlabs_check(ip: str, api_key: str) -> Dict[str, Any]:
    """Verifica fraude por IP con FraudLabs Pro."""
    url = f"https://api.fraudlabspro.com/v1/ip2location/{ip}"
    params = {"key": api_key, "format": "json"}
    return make_request(url, params=params)

# ==================== HERRAMIENTAS PARA DESARROLLADORES ====================

def github_search_repos(query: str, token: Optional[str] = None) -> Dict[str, Any]:
    """Busca repositorios en GitHub."""
    url = "https://api.github.com/search/repositories"
    params = {"q": query}
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return make_request(url, headers=headers, params=params)

def hackerone_programs() -> Dict[str, Any]:
    """Lista programas públicos en HackerOne (requiere token para datos completos)."""
    url = "https://api.hackerone.com/v1/hackers/programs"
    headers = {"Accept": "application/json"}
    # Requiere autenticación
    return {"note": "HackerOne API requiere autenticación - usar para programas públicos con token adecuado"}

# ==================== RECURSOS LEGALES ====================

# Placeholder para APIs legales (varían mucho por jurisdicción)

def main():
    parser = argparse.ArgumentParser(description="Herramientas profesionales de ciberseguridad")
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    # --- INTELIGENCIA ---
    parser_intel = subparsers.add_parser("intel", help="Inteligencia de amenazas y OSINT")
    intel_sub = parser_intel.add_subparsers(dest="intel_action")

    # Shodan
    p_shodan = intel_sub.add_parser("shodan", help="Buscar en Shodan")
    p_shodan.add_argument("query", help="Consulta de búsqueda")
    p_shodan.add_argument("--key", required=True, help="API key de Shodan")

    # Censys
    p_censys = intel_sub.add_parser("censys", help="Buscar en Censys")
    p_censys.add_argument("query", help="Consulta de búsqueda")
    p_censys.add_argument("--id", required=True, help="API ID")
    p_censys.add_argument("--secret", required=True, help="API Secret")

    # BinaryEdge
    p_binary = intel_sub.add_parser("binary", help="Buscar en BinaryEdge")
    p_binary.add_argument("query", help="Consulta de búsqueda")
    p_binary.add_argument("--key", required=True, help="API key")

    # GreyNoise
    p_grey = intel_sub.add_parser("greynoise", help="Consultar IP en GreyNoise")
    p_grey.add_argument("ip", help="Dirección IP")
    p_grey.add_argument("--key", required=True, help="API key")

    # VirusTotal
    p_vt = intel_sub.add_parser("virustotal", help="Escanear en VirusTotal")
    p_vt.add_argument("resource", help="URL o hash a escanear")
    p_vt.add_argument("--key", required=True, help="API key")

    # --- MALWARE ---
    parser_mal = subparsers.add_parser("malware", help="Análisis de malware")
    mal_sub = parser_mal.add_subparsers(dest="malware_action")

    p_urlscan = mal_sub.add_parser("urlscan", help="Escanear URL en URLScan.io")
    p_urlscan.add_argument("url", help="URL a escanear")
    p_urlscan.add_argument("--key", required=True, help="API key")

    p_malbazaar = mal_sub.add_parser("malbazaar", help="Consultar hash en MalwareBazaar")
    p_malbazaar.add_argument("hash", help="Hash MD5/SHA1/SHA256")

    # --- VULNERABILIDADES ---
    parser_vuln = subparsers.add_parser("vuln", help="Evaluación de vulnerabilidades")
    vuln_sub = parser_vuln.add_subparsers(dest="vuln_action")

    p_nvd = vuln_sub.add_parser("nvd", help="Buscar CVE en NVD")
    p_nvd.add_argument("cve", help="ID de la CVE (ej: CVE-2021-34527)")

    p_vuldb = vuln_sub.add_parser("vuldb", help="Buscar en VulDB")
    p_vuldb.add_argument("query", help="Término de búsqueda")
    p_vuldb.add_argument("--key", required=True, help="API key")

    # --- RED ---
    parser_net = subparsers.add_parser("network", help="Seguridad de red y reputación de IP")
    net_sub = parser_net.add_subparsers(dest="network_action")

    p_abuse = net_sub.add_parser("abuseipdb", help="Verificar IP en AbuseIPDB")
    p_abuse.add_argument("ip", help="Dirección IP")
    p_abuse.add_argument("--key", required=True, help="API key")

    p_ipinfo = net_sub.add_parser("ipinfo", help="Consultar información de IP (gratuita)")
    p_ipinfo.add_argument("ip", help="Dirección IP")

    # --- WEB ---
    parser_web = subparsers.add_parser("web", help="Seguridad de aplicaciones web")
    web_sub = parser_web.add_subparsers(dest="web_action")

    p_safebrowse = web_sub.add_parser("safebrowsing", help="Verificar URL con Google Safe Browsing")
    p_safebrowse.add_argument("url", help="URL a verificar")
    p_safebrowse.add_argument("--key", required=True, help="API key de Google")

    p_urlscan_result = web_sub.add_parser("urlscan_result", help="Obtener resultado de URLScan.io")
    p_urlscan_result.add_argument("scan_id", help="ID del escaneo")
    p_urlscan_result.add_argument("--key", required=True, help="API key")

    # --- AUTENTICACIÓN ---
    parser_auth = subparsers.add_parser("auth", help="Autenticación y seguridad de cuentas")
    auth_sub = parser_auth.add_subparsers(dest="auth_action")

    p_hibp = auth_sub.add_parser("hibp", help="Verificar brechas en HaveIBeenPwned")
    p_hibp.add_argument("account", help="Correo electrónico o usuario")

    # --- CRIPTOGRAFÍA ---
    parser_crypto = subparsers.add_parser("crypto", help="Criptografía y cifrado")
    crypto_sub = parser_crypto.add_subparsers(dest="crypto_action")

    p_hash = crypto_sub.add_parser("hashdecrypt", help="Intentar descifrar hash (ejemplo)")
    p_hash.add_argument("hash", help="Valor hash")
    p_hash.add_argument("--type", default="md5", help="Tipo de hash (md5, sha1, etc)")

    # --- FRAUDE ---
    parser_fraud = subparsers.add_parser("fraud", help="Detección de fraude")
    fraud_sub = parser_fraud.add_subparsers(dest="fraud_action")

    p_fraudlabs = fraud_sub.add_parser("fraudlabs", help="Verificar fraude por IP")
    p_fraudlabs.add_argument("ip", help="Dirección IP")
    p_fraudlabs.add_argument("--key", required=True, help="API key de FraudLabs Pro")

    # --- DESARROLLADORES ---
    parser_dev = subparsers.add_parser("dev", help="Herramientas para desarrolladores")
    dev_sub = parser_dev.add_subparsers(dest="dev_action")

    p_github = dev_sub.add_parser("github", help="Buscar repositorios en GitHub")
    p_github.add_argument("query", help="Consulta de búsqueda")
    p_github.add_argument("--token", help="Token personal de GitHub (opcional para rate limits)")

    p_h1 = dev_sub.add_parser("hackerone", help="Información sobre programas HackerOne")
    p_h1.add_argument("--token", help="Token de HackerOne (requerido para datos completos)")

    # --- LEGAL ---
    parser_legal = subparsers.add_parser("legal", help="Recursos para investigación y ley")
    parser_legal.add_argument("--info", action="store_true", help="Mostrar información sobre recursos legales disponibles")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Ejecutar según comando
    if args.command == "intel":
        if args.intel_action == "shodan":
            result = shodan_search(args.query, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.intel_action == "censys":
            result = censys_search(args.query, args.id, args.secret)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.intel_action == "binary":
            result = binary_edge_search(args.query, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.intel_action == "greynoise":
            result = greynoise_query(args.ip, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.intel_action == "virustotal":
            result = virustotal_scan(args.resource, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_intel.print_help()

    elif args.command == "malware":
        if args.malware_action == "urlscan":
            result = urlscan_scan(args.url, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.malware_action == "malbazaar":
            result = malwarebazaar_get_info(args.hash)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_mal.print_help()

    elif args.command == "vuln":
        if args.vuln_action == "nvd":
            result = nvd_search_cve(args.cve)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.vuln_action == "vuldb":
            result = vuldb_search(args.query, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_vuln.print_help()

    elif args.command == "network":
        if args.network_action == "abuseipdb":
            result = abuseipdb_check(args.ip, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.network_action == "ipinfo":
            result = ip_reputation_check(args.ip)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_net.print_help()

    elif args.command == "web":
        if args.web_action == "safebrowsing":
            result = google_safe_browsing_lookup(args.url, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.web_action == "urlscan_result":
            result = urlscan_result(args.scan_id, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_web.print_help()

    elif args.command == "auth":
        if args.auth_action == "hibp":
            result = haveibeenpwned_breach(args.account)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_auth.print_help()

    elif args.command == "crypto":
        if args.crypto_action == "hashdecrypt":
            result = hash_decrypt(args.hash, args.type)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_crypto.print_help()

    elif args.command == "fraud":
        if args.fraud_action == "fraudlabs":
            result = fraudlabs_check(args.ip, args.key)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_fraud.print_help()

    elif args.command == "dev":
        if args.dev_action == "github":
            result = github_search_repos(args.query, args.token)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.dev_action == "hackerone":
            result = hackerone_programs()
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            parser_dev.print_help()

    elif args.command == "legal":
        if args.info:
            print("""Recursos legales disponibles mediante APIs:
- APIs de registros públicos (varían por país)
- APIs de tribunales y jurisprudencia
- APIs de propiedad intelectual
- APIs de regulación financiera
Nota: Estas suelen requerir acuerdos específicos y no son tan estándar como las de seguridad.""")
        else:
            parser_legal.print_help()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()