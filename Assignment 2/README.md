# DNS Resolver - Iterative and Recursive Lookup

This project implements a DNS resolution system that supports both **iterative** and **recursive** DNS lookups. The system is built using Python and the `dnspython` library. It allows users to resolve domain names to IP addresses using either iterative or recursive methods.

---

## Table of Contents
1. [Introduction](#introduction)
2. [Requirements](#requirements)
3. [Usage] (#usage)
4. [Implementation Details](#implementation-details)
5. [Contributors](#contributors)

---

## Introduction

The Domain Name System (DNS) is a hierarchical system that translates human-readable domain names (e.g., `google.com`) into IP addresses (e.g., `142.250.194.78`). This project implements two types of DNS resolution:

1. **Iterative DNS Lookup**: The resolver queries DNS servers in a hierarchical manner, starting from the root servers, then top-level domain (TLD) servers, and finally authoritative servers.
2. **Recursive DNS Lookup**: The resolver delegates the entire resolution process to an external DNS resolver (e.g., the system's default resolver).

---

## Requirements

To run this project, you need the following:

- **Python 3.x**: The code is written in Python 3.
- **dnspython library**: Install the library using pip:

```bash
pip install dnspython
```

## Usage 

To use the DNS resolver, run the script with the following command:
```bash
python3 dns_resolver.py <mode> <domain>
```
Where:

- \<mode> is either iterative or recursive

- domain is the domain name to resolve (e.g., example.com)

## Implementation Details
### Iterative DNS Lookup ###


#### Process: ####

The resolver starts with a predefined list of root DNS servers.

It sends a DNS query to one of the root servers for the given domain.

If the root server does not have the answer, it returns a referral to the next level of nameservers (TLD servers).

The resolver then queries a TLD server, which provides authoritative nameservers.

The authoritative nameserver provides the final IP address of the domain.

The IP address is printed as the result.

#### Key Features: ####

Extracts NS records from the authority section of the response.

Resolves NS hostnames to IP addresses for the next query step.

Efficiently follows the hierarchy of Root → TLD → Authoritative servers.

Handles timeouts, unreachable servers, and resolution failures.

### Recursive DNS Lookup ###

#### Process: ####

Uses the system’s default resolver (e.g., Google DNS or local ISP resolver) to perform the lookup.

The system resolver recursively queries DNS servers until it finds the IP address or fails.

The final IP address is displayed.

#### Key Features: ####

Uses the dns.resolver.Resolver() method to perform recursive resolution.

Automatically follows the hierarchy of DNS queries without user intervention.

Handles resolution errors gracefully.

### Error Handling ###

**Timeouts:** If a query exceeds the set time limit, an error is displayed.

**NXDOMAIN:** If the domain does not exist, the error is logged.

**NoAnswer:** If no valid response is received, an appropriate message is shown.

**Connection Errors:** If a nameserver is unreachable, the program retries with another server.

**Invalid Inputs:** The script checks for incorrect arguments and informs the user.


## Contributors and contributions ##
Ankit Kaushik (220158)- 33.33% Recursive Lookup (With Comments)

Devansh Agrawal (220340) -33.33% Iterative Lookup (With Comments)

Harshit Srivastava (220444)- 33.33% Name Server Extraction, proper output formatting and Readme