import subprocess
import sys
import re
import time
from collections import defaultdict

# ---------- run_dig with timing ----------
def run_dig(command):
    print("\nRunning:", " ".join(command))
    print("-" * 60)

    start = time.time()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        elapsed_ms = int((time.time() - start) * 1000)

        output = result.stdout + result.stderr
        if output.strip():
            print(output)
        print("-" * 60)

        return output, result.returncode == 0, elapsed_ms
    except subprocess.TimeoutExpired:
        print("Command timed out")
        return "", False, None
    except Exception as e:
        print(f"Error: {e}")
        return "", False, None


# ---------- Categorization helpers ----------
def is_vuln_like(name):
    return any(k in name.lower() for k in
               ['cmdexec', 'sqli', 'xss', 'sshock', '_acme'])

def is_infrastructure(name):
    return any(k in name.lower() for k in
               ['vpn', 'owa', 'internal', 'office', 'dc-', 'staging'])

def is_contact(name):
    return any(k in name.lower() for k in
               ['contact', 'email', 'robin', 'pippa'])

def is_fun(name):
    return any(k in name.lower() for k in
               ['hello', 'dzc', 'dr', 'home'])


# ---------- Your original parser (unchanged logic) ----------
def parse_axfr_output(output, domain):
    lines = output.strip().split('\n')
    records = []
    subdomains = defaultdict(list)
    main_records = []

    for line in lines:
        if line.strip() and not line.startswith((';;', ' ')):
            parts = re.split(r'\s+', line.strip(), maxsplit=4)
            if len(parts) >= 5:
                name, ttl, cls, typ, data = parts
                if name.endswith('.'):
                    name = name.rstrip('.')

                rec = {
                    'name': name,
                    'ttl': ttl,
                    'type': typ,
                    'data': data
                }
                records.append(rec)

                if name == domain.rstrip('.'):
                    main_records.append(rec)
                else:
                    subdomains[name].append(rec)

    return records, main_records, dict(subdomains)


# ---------- New clean (emoji-free) output ----------
def print_aesthetic_results(domain, output, elapsed_ms, ns_server):
    records, main_records, subdomains = parse_axfr_output(output, domain)

    # Try to extract IP of the server from dig output (best-effort)
    server_ip = "unknown"
    m = re.search(r'\(([\d\.]+)\)', output)
    if m:
        server_ip = m.group(1)

    print("\n" + "="*80)
    print(f"AXFR SUCCESS! Full Zone Dump: {domain}")
    print("="*80)

    print(f"""
TRANSFER COMPLETE
{len(records)} Records | {len(output)} bytes | {elapsed_ms}ms
Server: {ns_server.lstrip('@')} ({server_ip})

MAIN DOMAIN RECORDS
""")

    for r in main_records:
        print(f"{r['name']+'.':<30} {r['ttl']:<8} {r['type']:<6} {r['data']}")

    print(f"\nSUBDOMAINS DISCOVERED ({len(subdomains)})\n")

    infra, vuln, contact, fun = [], [], [], []

    for sub, recs in subdomains.items():
        main_rec = next((r for r in recs if r['type'] in ['A','AAAA','CNAME']), recs[0])
        line = f"├── {sub+'.':<35} -> {main_rec['data']}"

        if is_infrastructure(sub):
            infra.append(line)
        elif is_vuln_like(sub):
            vuln.append(line)
        elif is_contact(sub):
            contact.append(line)
        elif is_fun(sub):
            fun.append(line)

    print("INFRASTRUCTURE:")
    for l in infra:
        print(l)

    print("\nVULN-LIKE:")
    for l in vuln:
        print(l)

    print("\nCONTACT / INTEL:")
    for l in contact:
        print(l)

    print("\nFUN / TESTING:")
    for l in fun:
        print(l)

    print("\nATTACK SURFACE HIGHLIGHTS\n")

    print("HIGH VALUE TARGETS:")
    for i, t in enumerate(infra[:4], start=1):
        print(f"{i}. {t.replace('├── ','')}")

    print("\nPHISH TARGETS:")
    for c in contact:
        if "@" in c:
            email = re.search(r'[\w\.-]+@[\w\.-]+', c)
            if email:
                print(f"- {email.group(0)}")


# ---------- Main execution (your flow) ----------
domain = input("Enter website/domain: ").strip()
if not domain:
    sys.exit(1)

print("\nStep 1: Discovering nameservers...")
ns_output, _, _ = run_dig(["dig", "ns", domain, "+short"])

ns_server = input("\nEnter target nameserver for AXFR: ").strip()
if not ns_server.startswith('@'):
    ns_server = '@' + ns_server

print("\nStep 2: Attempting AXFR zone transfer...")
axfr_output, success, ms = run_dig(["dig", domain, ns_server, "AXFR"])

if success:
    print_aesthetic_results(domain, axfr_output, ms, ns_server)
    print("\nFULL ZONE TRANSFER SUCCEEDED.")
else:
    print("AXFR denied - running fallback enumeration...")
    fallback = ["mx", "txt", "aaaa", "a"]
    for rec in fallback:
        run_dig(["dig", rec, domain, ns_server, "+short"])
