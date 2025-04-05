import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import time
import dns.exception

# Root DNS servers for iterative resolution
ROOT_SERVERS = {
    "198.41.0.4": "Root (a.root-servers.net)",
    "199.9.14.201": "Root (b.root-servers.net)",
    "192.33.4.12": "Root (c.root-servers.net)",
    "199.7.91.13": "Root (d.root-servers.net)",
    "192.203.230.10": "Root (e.root-servers.net)"
}

TIMEOUT = 3  # Large enough timeout in seconds for DNS queries

def send_dns_query(server, domain):
    """
    Sends a DNS query to the specified server for an A record.
    
    Args:
        server (str): IP address of the DNS server.
        domain (str): Domain name to query.
    
    Returns:
        dns.message.Message: Response if successful, None otherwise.
    """
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A)
        response = dns.query.udp(query, server, timeout=TIMEOUT)
        return response
    except dns.exception.Timeout:
        print(f"[ERROR] Timeout after {TIMEOUT} seconds querying {server} for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"[ERROR] Domain {domain} does not exist (NXDOMAIN)")
        return None
    except Exception as e:
        print(f"[ERROR] Query to {server} failed: {str(e)}")
        return None

def extract_next_nameservers(response):
    """
    Extracts and resolves nameserver IPs from the response's authority section.
    
    Args:
        response (dns.message.Message): DNS response containing authority records.
    
    Returns:
        list: List of IP addresses of next nameservers.
    """
    ns_ips = []
    ns_names = []

    # Extract NS records from authority section
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                ns_name = rr.to_text()
                ns_names.append(ns_name)
                print(f"Extracted NS hostname: {ns_name}")

    # Resolve NS hostnames to IPs
    resolver = dns.resolver.Resolver()
    for ns_name in ns_names:
        try:
            answers = resolver.resolve(ns_name, 'A')
            for rdata in answers:
                ns_ip = rdata.to_text()
                ns_ips.append(ns_ip)
                print(f"Resolved {ns_name} to {ns_ip}")
        except dns.resolver.NoAnswer:
            print(f"[ERROR] No A record found for {ns_name}")
        except dns.resolver.NXDOMAIN:
            print(f"[ERROR] Nameserver {ns_name} does not exist")
        except dns.exception.Timeout:
            print(f"[ERROR] Timeout resolving {ns_name}")
        except Exception as e:
            print(f"[ERROR] Failed to resolve {ns_name}: {str(e)}")

    return ns_ips

def iterative_dns_lookup(domain):
    """
    Performs iterative DNS resolution starting from root servers.
    
    Args:
        domain (str): Domain name to resolve.
    """
    print(f"[Iterative DNS lookup] Resolving {domain}")
    next_ns_list = list(ROOT_SERVERS.keys())  # Start with root servers
    stage = "ROOT"

    while next_ns_list:
        ns_ip = next_ns_list.pop(0)
        response = send_dns_query(ns_ip, domain)

        if response:
            print(f"[DEBUG] Querying {stage} server {ns_ip} - SUCCESS")

            # Check if answer section contains A record
            if response.answer:
                for answer in response.answer:
                    if answer.rdtype == dns.rdatatype.A:
                        print(f"[SUCCESS] {domain} -> {answer[0].to_text()}")
                        return

            # Extract next nameservers
            next_ns_list = extract_next_nameservers(response)
            if not next_ns_list:
                print(f"[ERROR] No further nameservers found at {stage} stage")
                return

            # Update stage
            if stage == "ROOT":
                stage = "TLD"
            elif stage == "TLD":
                stage = "AUTH"
        else:
            print(f"[ERROR] Query to {stage} server {ns_ip} failed")
            if not next_ns_list:
                print("[ERROR] Resolution failed: no more nameservers to try")
                return

    print("[ERROR] Resolution failed: exhausted all nameservers")

def recursive_dns_lookup(domain):
    """
    Performs recursive DNS resolution using the system's resolver.
    
    Args:
        domain (str): Domain name to resolve.
    """
    print(f"[Recursive DNS lookup] Resolving {domain}")
    try:
        resolver = dns.resolver.Resolver()
        answers_ns = resolver.resolve(domain, "NS")
        for rdata in answers_ns:
            print("[SUCCESS]", domain, "->", rdata.to_text())

        answers_a = resolver.resolve(domain, "A")
        for rdata in answers_a:
            print("[SUCCESS]", domain, "->", rdata.to_text())
    except dns.resolver.NXDOMAIN:
        print(f"[ERROR] Domain {domain} does not exist (NXDOMAIN)")
    except dns.resolver.NoAnswer:
        print(f"[ERROR] No A record found for {domain}")
    except dns.exception.Timeout:
        print(f"[ERROR] Timeout during recursive lookup")
    except Exception as e:
        print(f"[ERROR] Recursive lookup failed: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3 or sys.argv[1] not in {"iterative", "recursive"}:
        print("Usage: python3 dnsresolver.py <iterative|recursive> <domain>")
        sys.exit(1)

    mode = sys.argv[1]
    domain = sys.argv[2]
    start_time = time.time()

    if mode == "iterative":
        iterative_dns_lookup(domain)
    else:
        recursive_dns_lookup(domain)

    print(f"Time taken: {time.time() - start_time:.3f} seconds")