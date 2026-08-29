#!/usr/bin/env python3

import requests
import argparse
import json
import sys
import os
import subprocess
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════╗
║        Subdomain Tester - YaresSec       ║
║      Subdomain Discovery & HTTP Test     ║
╚══════════════════════════════════════════╝
"""

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "wiki", "app", "web", "portal", "cdn", "static",
    "vpn", "ns1", "ns2", "mx", "smtp", "pop3", "imap",
    "git", "gitlab", "jenkins", "jira", "confluence",
    "grafana", "prometheus", "kibana", "elastic",
    "monitor", "status", "help", "support", "ticket",
    "cloud", "aws", "azure", "gcp", "s3", "bucket",
    "login", "auth", "sso", "oauth", "idp",
    "dashboard", "analytics", "metrics", "logs",
    "search", "docs", "download", "upload",
    "remote", "ssh", "rdp", "terminal", "shell",
    "console", "manager", "management", "config",
    "backup", "db", "database", "sql", "mysql",
    "redis", "memcached", "rabbitmq", "kafka",
    "jenkins", "travis", "circleci", "ci", "cd",
    "stage", "prod", "production", "development",
    "release", "beta", "alpha", "demo", "sandbox",
    "intranet", "internal", "external", "public",
    "partner", "vendor", "supplier", "customer",
    "news", "events", "media", "gallery", "images",
    "video", "tv", "radio", "stream", "live",
    "forum", "community", "chat", "discord",
    "shop", "store", "cart", "checkout", "payment",
    "track", "tracking", "ship", "delivery",
    "career", "jobs", "hr", "employee",
    "office", "sharepoint", "outlook", "owa",
    "lync", "skype", "teams", "zoom", "meet",
    "phone", "call", "voip", "sip",
    "gateway", "proxy", "lb", "loadbalancer",
    "firewall", "waf", "ids", "ips",
    "security", "audit", "compliance",
    "report", "billing", "invoice", "account",
    "profile", "settings", "preferences",
    "mfa", "2fa", "otp", "totp",
    "verify", "validate", "confirm",
    "signup", "register", "signin",
    "password", "reset", "forgot",
    "feedback", "survey", "poll",
    "webmail", "roundcube", "squirrelmail",
    "phpmyadmin", "phpadmin", "adminer",
    "swagger", "api-docs", "api-doc",
    "graphql", "graphiql", "gql",
    "sockjs", "socket", "websocket",
    "mqtt", "coap", "amqp",
    "broker", "queue", "pubsub",
    "docker", "k8s", "kubernetes",
    "helm", "istio", "envoy",
    "service", "services", "micro",
    "soap", "rest", "grpc", "rpc",
    "solr", "elasticsearch", "mongo",
    "cassandra", "couchdb", "neo4j",
    "airflow", "druid", "superset",
    "jupyter", "notebook", "lab",
    "tensorflow", "pytorch", "ml",
    "ai", "bot", "chatbot",
    "iot", "device", "sensor",
    "edge", "fog", "mesh",
    "cdn", "akamai", "cloudfront",
    "fastly", "cloudflare", "incapsula",
    "sucuri", "stackpath", "keycdn",
    "ns", "dns", "bind", "unbound",
    "dhcp", "tftp", "ntp", "ldap",
    "radius", "tacacs", "kerberos",
    "ca", "pki", "cert", "crl",
    "ocsp", "timestamp", "tsp",
    "hsm", "vault", "key",
    "license", "activation", "entitlement",
    "telemetry", "collector", "ingest",
    "data", "api-data", "data-api",
    "feeds", "rss", "atom", "xml",
    "json", "rest-api", "restapi",
    "public-api", "private-api", "internal-api",
    "webhook", "callback", "notify",
    "notification", "push", "alert",
    "sms", "email", "mailgun", "sendgrid",
    "twilio", "nexmo", "plivo",
    "pixel", "tracker", "analytics",
    "ad", "ads", "adserver",
    "sponsor", "affiliate", "referral",
    "lp", "landing", "lander",
    "promo", "promotion", "campaign",
    "contest", "sweepstakes", "giveaway",
    "welcome", "onboarding", "getting-started",
    "faq", "knowledgebase", "kb",
    "statuspage", "status-page", "uptime",
    "maintenance", "maintenance-mode",
    "error", "errors", "exception",
    "debug", "logging", "logger",
    "syslog", "graylog", "logstash",
    "fluentd", "fluentbit", "vector",
    "splunk", "sumologic", "datadog",
    "newrelic", "dynatrace", "appdynamics",
    "instana", "jaeger", "zipkin",
    "skywalking", "pinpoint", "opentelemetry",
    "thanos", "cortex", "victoriametrics",
    "influxdb", "timescaledb", "clickhouse",
    "vertica", "druid", "pinot",
    "presto", "trino", "hive",
]

def c(color, text):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def print_banner():
    print(c("cyan", BANNER))
    print(f"{c('bold', '[*]')} Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{c('bold', '[*]')} Developed by {c('green', 'YaresSec')}\n")

def load_domains(domain_file):
    if not os.path.exists(domain_file):
        print(f"{c('red', '[!]')} File not found: {domain_file}")
        sys.exit(1)
    with open(domain_file) as f:
        return [d.strip() for d in f if d.strip()]

def resolve(domain):
    try:
        r = subprocess.run(
            ["host", domain],
            capture_output=True, text=True, timeout=5,
        )
        return "has address" in r.stdout or "has IPv6 address" in r.stdout
    except Exception:
        return False

def discover_subfinder(domain, all_sources=False, recursive=False):
    print(f"  {c('bold', '[~]')} Running subfinder on {c('cyan', domain)}...")
    cmd = ["subfinder", "-d", domain]
    if all_sources:
        cmd.append("-all")
    if recursive:
        cmd.append("-recursive")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        subs = [
            s.strip() for s in r.stdout.splitlines()
            if s.strip() and not s.strip().startswith("[")
        ]
        if subs:
            print(f"  {c('green', '[+]')} subfinder found {c('bold', str(len(subs)))} subdomains")
        else:
            print(f"  {c('yellow', '[-]')} subfinder found nothing")
        return subs
    except subprocess.TimeoutExpired:
        print(f"  {c('red', '[!]')} subfinder timed out (90s)")
        return []
    except FileNotFoundError:
        print(f"  {c('yellow', '[!]')} subfinder not installed, skipping")
        return []

def discover_crtsh(domain):
    print(f"  {c('bold', '[~]')} Fetching crt.sh for {c('cyan', domain)}...")
    subs = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value", "")
                for s in name.splitlines():
                    s = s.strip().lower().lstrip("*.")
                    if s.endswith(f".{domain}") or s == domain:
                        subs.add(s)
            print(f"  {c('green', '[+]')} crt.sh found {c('bold', str(len(subs)))} subdomains")
        else:
            print(f"  {c('yellow', '[-]')} crt.sh returned {r.status_code}")
    except Exception as e:
        print(f"  {c('yellow', '[-]')} crt.sh error: {e}")
    return list(subs)

def discover_alienvault(domain):
    print(f"  {c('bold', '[~]')} Fetching AlienVault OTX for {c('cyan', domain)}...")
    subs = set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200:
            for entry in r.json().get("passive_dns", []):
                host = entry.get("hostname", "")
                if host.endswith(f".{domain}"):
                    subs.add(host.lower())
            print(f"  {c('green', '[+]')} AlienVault found {c('bold', str(len(subs)))} subdomains")
        else:
            print(f"  {c('yellow', '[-]')} AlienVault returned {r.status_code}")
    except Exception as e:
        print(f"  {c('yellow', '[-]')} AlienVault error: {e}")
    return list(subs)

def discover_wayback(domain):
    print(f"  {c('bold', '[~]')} Fetching Wayback Machine for {c('cyan', domain)}...")
    subs = set()
    try:
        r = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200:
            for entry in r.json()[1:]:
                url = entry[0] if isinstance(entry, list) else ""
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
                if host.endswith(f".{domain}"):
                    subs.add(host.lower())
            print(f"  {c('green', '[+]')} Wayback found {c('bold', str(len(subs)))} subdomains")
        else:
            print(f"  {c('yellow', '[-]')} Wayback returned {r.status_code}")
    except Exception as e:
        print(f"  {c('yellow', '[-]')} Wayback error: {e}")
    return list(subs)

def discover_bruteforce(domain, wordlist=None):
    words = BUILTIN_WORDLIST
    src = "built-in wordlist"
    if wordlist:
        if not os.path.exists(wordlist):
            print(f"  {c('red', '[!]')} Wordlist not found: {wordlist}")
            return []
        with open(wordlist) as f:
            words = [w.strip() for w in f if w.strip()]
        src = wordlist

    print(f"  {c('bold', '[~]')} DNS bruteforce on {c('cyan', domain)} ({len(words)} words, {src})...")
    subs = set()
    found = 0
    total = len(words)

    with ThreadPoolExecutor(max_workers=50) as executor:
        future_map = {}
        for word in words:
            sub = f"{word}.{domain}"
            future_map[executor.submit(resolve, sub)] = sub

        for i, future in enumerate(as_completed(future_map)):
            sub = future_map[future]
            if future.result():
                subs.add(sub)
                found += 1
                sys.stdout.write(f"\r    {c('green', f'[{found}]')} {sub:50}")
                sys.stdout.flush()
            if (i + 1) % 100 == 0:
                sys.stdout.write(f"\r    Progress: {i+1}/{total} | Found: {found}")
                sys.stdout.flush()

    print(f"\n  {c('green', '[+]')} Bruteforce found {c('bold', str(len(subs)))} subdomains")
    return list(subs)

def check_domain(domain):
    results = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            results.append({
                "domain": domain,
                "url": url,
                "scheme": scheme,
                "status": r.status_code,
                "title": extract_title(r.text),
                "server": r.headers.get("Server", ""),
                "content_length": len(r.content),
            })
        except requests.exceptions.ConnectionError:
            results.append({
                "domain": domain,
                "url": url,
                "scheme": scheme,
                "status": 0,
                "error": "Connection refused / unreachable",
            })
        except requests.exceptions.Timeout:
            results.append({
                "domain": domain,
                "url": url,
                "scheme": scheme,
                "status": 0,
                "error": "Timeout",
            })
        except Exception as e:
            results.append({
                "domain": domain,
                "url": url,
                "scheme": scheme,
                "status": 0,
                "error": str(e),
            })
    return results

def extract_title(html):
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else ""

def sort_key(result):
    s = result.get("status", 0)
    if s == 200:
        return 0
    if 200 <= s < 300:
        return 1
    if 300 <= s < 400:
        return 2
    if 400 <= s < 500:
        return 3
    if 500 <= s < 600:
        return 4
    return 5

def print_result(result):
    s = result.get("status", 0)
    url = result.get("url", "")
    error = result.get("error", "")

    if s == 0:
        status_str = c("red", f"[DOWN]")
        detail = f"({error})"
    elif s == 200:
        status_str = c("green", f"[{s}]")
        title = result.get("title", "")
        detail = f"| {result.get('server', '')} | {title}" if title else f"| {result.get('server', '')}"
    elif 300 <= s < 400:
        status_str = c("yellow", f"[{s}]")
        detail = f"| {result.get('server', '')}"
    elif 400 <= s < 500:
        status_str = c("red", f"[{s}]")
        detail = f"| {result.get('server', '')}"
    elif 500 <= s < 600:
        status_str = c("yellow", f"[{s}]")
        detail = f"| {result.get('server', '')}"
    else:
        status_str = c("blue", f"[{s}]")
        detail = f"| {result.get('server', '')}"

    print(f"  {status_str} {c('cyan', url):45} {detail}")

def output_txt(results, filepath):
    with open(filepath, "w") as f:
        for r in results:
            s = r.get("status", 0)
            url = r.get("url", "")
            title = r.get("title", "")
            server = r.get("server", "")
            if s == 0:
                f.write(f"[DOWN] {url} ({r.get('error', '')})\n")
            elif s == 200:
                f.write(f"[{s}] {url} | {server} | {title}\n".rstrip(" |") + "\n")
            else:
                f.write(f"[{s}] {url} | {server}\n".rstrip(" |") + "\n")

def output_json(results, filepath):
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def output_csv(results, filepath):
    with open(filepath, "w") as f:
        f.write("status,url,scheme,domain,server,title,error,content_length\n")
        for r in results:
            f.write(
                f"{r.get('status', '')},"
                f"{r.get('url', '')},"
                f"{r.get('scheme', '')},"
                f"{r.get('domain', '')},"
                f"{r.get('server', '')},"
                f"{r.get('title', '')},"
                f"{r.get('error', '')},"
                f"{r.get('content_length', '')}\n"
            )

def output_subdomains(subdomains, filepath):
    with open(filepath, "w") as f:
        for d in subdomains:
            f.write(d + "\n")

OUTPUT_FUNCTIONS = {
    "txt": output_txt,
    "json": output_json,
    "csv": output_csv,
}

def main():
    parser = argparse.ArgumentParser(
        description="SubHTTTest - Subdomain discovery & HTTP(S) status checker by YaresSec",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subtest.py -d tesla.com
  python3 subtest.py -d tesla.com --out=json
  python3 subtest.py -d tesla.com --all-sources --recursive
  python3 subtest.py -d tesla.com --no-test
  python3 subtest.py -d tesla.com --bruteforce --wordlist big.txt
  python3 subtest.py --domains lista.txt --out=csv -o resultado.csv
        """,
    )
    parser.add_argument(
        "-d", "--domain",
        help="Target domain to discover & test subdomains",
    )
    parser.add_argument(
        "--domains",
        help="File with existing subdomain list (skip discovery)",
    )
    parser.add_argument(
        "--out",
        choices=["txt", "json", "csv"],
        default="txt",
        help="Output format (default: txt)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (default: <domain>.<format>)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Threads for HTTP testing (default: 50)",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="Skip HTTP(S) testing, only discover & save subdomains",
    )
    parser.add_argument(
        "--all-sources",
        action="store_true",
        help="Use all subfinder sources (slower but more results)",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Use recursive subfinder sources",
    )
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="Skip subfinder enumeration",
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Enable DNS bruteforce (uses built-in wordlist or --wordlist)",
    )
    parser.add_argument(
        "--wordlist",
        help="Custom wordlist for DNS bruteforce",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress live HTTP test output",
    )

    args = parser.parse_args()

    if not args.domain and not args.domains:
        print(f"{c('red', '[!]')} Use -d <domain> or --domains <file>")
        sys.exit(1)

    print_banner()

    if args.domains:
        domains = load_domains(args.domains)
        src = args.domains
        print(f"{c('bold', '[+]')} Loaded {c('green', str(len(domains)))} domains from {src}")
    else:
        domain = args.domain
        subs = set()

        print(f"{c('bold', '[+]')} Target: {c('cyan', domain)}\n")
        print(f"{c('bold', '--- Discovery Phase ---')}\n")

        if not args.no_subfinder:
            subs.update(discover_subfinder(domain, args.all_sources, args.recursive))

        subs.update(discover_crtsh(domain))
        subs.update(discover_alienvault(domain))
        subs.update(discover_wayback(domain))

        if args.bruteforce:
            subs.update(discover_bruteforce(domain, args.wordlist))

        subs = sorted(s for s in subs if s)
        domains = list(dict.fromkeys(subs))

        if not domains:
            print(f"\n{c('red', '[!]')} No subdomains found for {domain}")
            sys.exit(0)

        print(f"\n{c('bold', '---')}")
        print(f"{c('bold', '[+]')} Total unique subdomains: {c('green', str(len(domains)))}")

        if args.no_test:
            output_file = args.output or f"{domain}-subs.txt"
            output_subdomains(domains, output_file)
            print(f"  {c('bold', 'Saved list:')} {c('green', output_file)}")
            sys.exit(0)

    print(f"\n{c('bold', '--- HTTP(S) Testing Phase ---')}\n")
    print(f"{c('bold', '[+]')} Testing {c('green', str(len(domains)))} domain(s) | Threads: {args.threads} | Output: {args.out}\n")

    all_results = []
    processed = 0
    total = len(domains)
    live_count = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_domain, d): d for d in domains}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                results = future.result()
                for res in results:
                    s = res.get("status", 0)
                    if s != 0:
                        live_count += 1
                    if not args.quiet:
                        print_result(res)
                all_results.extend(results)
            except Exception as e:
                if not args.quiet:
                    print(f"  {c('red', '[ERROR]')} {domain}: {e}")
            processed += 1
            sys.stdout.write(f"\r{c('bold', '[~]')} Progress: {processed}/{total}")
            sys.stdout.flush()

    print(f"\n\n{c('bold', '[+]')} Scan complete!")
    print(f"  {c('green', 'Alive:')} {live_count}  {c('red', 'Dead:')} {total * 2 - live_count}")

    all_results.sort(key=sort_key)

    default_name = args.domain if args.domain else "domains"
    output_file = args.output or f"{default_name}.{args.out}"
    out_fn = OUTPUT_FUNCTIONS.get(args.out, output_txt)
    out_fn(all_results, output_file)

    print(f"  {c('bold', 'Saved:')} {c('green', output_file)}")

    up = [r for r in all_results if r.get("status", 0) == 200]
    print(f"\n{c('bold', 'Summary:')}")
    print(f"  {c('green', f'200 OK:')} {len(up)}")
    for r in up[:5]:
        print(f"    {c('cyan', r['url'])}")
    if len(up) > 5:
        print(f"    ... and {len(up) - 5} more")

if __name__ == "__main__":
    main()
