# DNS Resolver - Iterative and Recursive Lookup
# This script implements DNS resolution using both iterative and recursive methods.
# It uses the dnspython library to query DNS servers and resolve domain names to IP addresses.
# Contributors: [Your Names and Roll Numbers Here, e.g., Ankit Kaushik (220158)]

import dns.message    # For constructing and parsing DNS messages
import dns.query      # For sending DNS queries over UDP
import dns.rdatatype  # For specifying DNS record types (e.g., A, NS)
import dns.resolver   # For performing recursive DNS resolutions
import time           # For measuring execution time
import dns.exception  # For handling DNS-specific exceptions

# Root DNS servers for iterative resolution
# These are well-known root servers, each mapped to a descriptive name for clarity.
ROOT_SERVERS = {
    "198.41.0.4": "Root (a.root-servers.net)",
    "199.9.14.201": "Root (b.root-servers.net)",
    "192.33.4.12": "Root (c.root-servers.net)",
    "199.7.91.13": "Root (d.root-servers.net)",
    "192.203.230.10": "Root (e.root-servers.net)"
}

TIMEOUT = 3  # Timeout in seconds for DNS queries; 3 seconds is sufficient for most servers

def send_dns_query(server, domain):
    """
    Sends a DNS query to the specified server for an A record of the given domain.

    Args:
        server (str): IP address of the DNS server to query (e.g., "198.41.0.4").
        domain (str): Domain name to resolve (e.g., "google.com").

    Returns:
        dns.message.Message: The DNS response object if successful, None if the query fails.

    Notes:
        - Uses UDP for lightweight, fast queries.
        - Handles specific exceptions to provide meaningful error messages.
    """
    try:
        # Create a DNS query message for an A (address) record
        query = dns.message.make_query(domain, dns.rdatatype.A)
        # Send the query over UDP with a timeout of 3 seconds
        response = dns.query.udp(query, server, timeout=TIMEOUT)
        return response
    except dns.exception.Timeout:
        # Handle case where server doesn't respond within the timeout period
        print(f"[ERROR] Timeout after {TIMEOUT} seconds querying {server} for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        # Handle case where the domain does not exist
        print(f"[ERROR] Domain {domain} does not exist (NXDOMAIN)")
        return None
    except Exception as e:
        # Catch any other unexpected errors during the query
        print(f"[ERROR] Query to {server} failed: {str(e)}")
        return None

def extract_next_nameservers(response):
    """
    Extracts nameserver (NS) records from the authority section and resolves them to IP addresses.

    Args:
        response (dns.message.Message): DNS response object containing authority records.

    Returns:
        list: List of IP addresses of the next authoritative nameservers.

    Notes:
        - Iterates through authority records to find NS records.
        - Resolves each NS hostname to an IP using a recursive resolver.
    """
    ns_ips = []  # List to store resolved IP addresses of nameservers
    ns_names = []  # List to store nameserver hostnames

    # Extract NS records from the authority section of the response
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:  # Check for nameserver records
            for rr in rrset:
                ns_name = rr.to_text()  # Convert NS record to text (hostname)
                ns_names.append(ns_name)
                print(f"Extracted NS hostname: {ns_name}")

    # Resolve each extracted NS hostname to an IP address
    resolver = dns.resolver.Resolver()  # Initialize a recursive resolver
    for ns_name in ns_names:
        try:
            # Query the A record for the nameserver hostname
            answers = resolver.resolve(ns_name, 'A')
            for rdata in answers:
                ns_ip = rdata.to_text()  # Convert IP to text format
                ns_ips.append(ns_ip)
                print(f"Resolved {ns_name} to {ns_ip}")
        except dns.resolver.NoAnswer:
            # Handle case where no A record exists for the nameserver
            print(f"[ERROR] No A record found for {ns_name}")
        except dns.resolver.NXDOMAIN:
            # Handle case where the nameserver hostname doesn't exist
            print(f"[ERROR] Nameserver {ns_name} does not exist")
        except dns.exception.Timeout:
            # Handle timeout during nameserver resolution
            print(f"[ERROR] Timeout resolving {ns_name}")
        except Exception as e:
            # Catch any other resolution errors
            print(f"[ERROR] Failed to resolve {ns_name}: {str(e)}")

    return ns_ips

def iterative_dns_lookup(domain):
    """
    Performs iterative DNS resolution starting from root servers through TLD and authoritative servers.

    Args:
        domain (str): Domain name to resolve (e.g., "example.com").

    Notes:
        - Iteratively queries servers, moving from ROOT -> TLD -> AUTH stages.
        - Stops when an A record is found or no further nameservers are available.
    """
    print(f"[Iterative DNS lookup] Resolving {domain}")
    next_ns_list = list(ROOT_SERVERS.keys())  # Initialize with root server IPs
    stage = "ROOT"  # Track current stage: ROOT, TLD, or AUTH

    while next_ns_list:  # Continue while there are nameservers to query
        ns_ip = next_ns_list.pop(0)  # Get and remove the first nameserver IP
        response = send_dns_query(ns_ip, domain)  # Send query to current server

        if response:  # If a response is received
            print(f"[DEBUG] Querying {stage} server {ns_ip} - SUCCESS")

            # Check if the answer section contains an A record
            if response.answer:
                for answer in response.answer:
                    if answer.rdtype == dns.rdatatype.A:  # Verify it's an A record
                        print(f"[SUCCESS] {domain} -> {answer[0].to_text()}")
                        return  # Exit once IP is found

            # If no answer, extract next nameservers from authority section
            next_ns_list = extract_next_nameservers(response)
            if not next_ns_list:
                # No more nameservers to query at this stage
                print(f"[ERROR] No further nameservers found at {stage} stage")
                return

            # Update the resolution stage for next iteration
            if stage == "ROOT":
                stage = "TLD"
            elif stage == "TLD":
                stage = "AUTH"
        else:
            # Query failed, report error and check if more servers are available
            print(f"[ERROR] Query to {stage} server {ns_ip} failed")
            if not next_ns_list:
                print("[ERROR] Resolution failed: no more nameservers to try")
                return

    # If loop exits without resolution, all nameservers were exhausted
    print("[ERROR] Resolution failed: exhausted all nameservers")

def recursive_dns_lookup(domain):
    """
    Performs recursive DNS resolution using the system's default resolver.

    Args:
        domain (str): Domain name to resolve (e.g., "google.com").

    Notes:
        - Queries both NS and A records to show nameservers and IP addresses.
        - Relies on the system's resolver for recursive resolution.
    """
    print(f"[Recursive DNS lookup] Resolving {domain}")
    try:
        resolver = dns.resolver.Resolver()  # Initialize the recursive resolver
        
        # Query NS records to display nameservers
        answers_ns = resolver.resolve(domain, "NS")
        for rdata in answers_ns:
            print("[SUCCESS]", domain, "->", rdata.to_text())  # Print each NS record

        # Query A records to get IP addresses
        answers_a = resolver.resolve(domain, "A")
        for rdata in answers_a:
            print("[SUCCESS]", domain, "->", rdata.to_text())  # Print each IP address

    except dns.resolver.NXDOMAIN:
        # Handle case where the domain does not exist
        print(f"[ERROR] Domain {domain} does not exist (NXDOMAIN)")
    except dns.resolver.NoAnswer:
        # Handle case where no records are returned
        print(f"[ERROR] No A record found for {domain}")
    except dns.exception.Timeout:
        # Handle timeout during recursive resolution
        print(f"[ERROR] Timeout during recursive lookup")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"[ERROR] Recursive lookup failed: {str(e)}")

if __name__ == "__main__":
    """
    Main execution block to handle command-line arguments and run the appropriate lookup.

    Command-line Args:
        sys.argv[1]: Mode ("iterative" or "recursive")
        sys.argv[2]: Domain name to resolve
    """
    import sys
    # Validate command-line arguments
    if len(sys.argv) != 3 or sys.argv[1] not in {"iterative", "recursive"}:
        print("Usage: python3 dnsresolver.py <iterative|recursive> <domain>")
        sys.exit(1)  # Exit with error code if arguments are invalid

    mode = sys.argv[1]    # Get the lookup mode
    domain = sys.argv[2]  # Get the domain name
    start_time = time.time()  # Record start time for performance measurement

    # Execute the selected DNS resolution mode
    if mode == "iterative":
        iterative_dns_lookup(domain)
    else:
        recursive_dns_lookup(domain)

    # Print the total time taken for the resolution
    print(f"Time taken: {time.time() - start_time:.3f} seconds")