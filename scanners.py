import os
import subprocess

class SubdomainScanner:
    def scan(self, target_url):
        subdomains = []
        # Use subfinder for subdomain enumeration
        subprocess.call(["subfinder", "-d", target_url, "-o", "subdomains.txt"])
        # Read the subdomains from the output file
        with open("subdomains.txt", "r") as file:
            subdomains = file.read().splitlines()
        return subdomains

class NmapScanner:
    def scan(self, target_url):
        open_ports = []
        # Use Nmap for port scanning and service detection
        subprocess.call(["nmap", "-p-", "-sV", target_url, "-oN", "nmap_output.txt"])
        # Read the open ports from the output file
        with open("nmap_output.txt", "r") as file:
            for line in file:
                if "/tcp" in line:
                    port = line.split("/")[0]
                    open_ports.append(port)
        return open_ports

class XssScanner:
    def scan(self, target_url):
        xss_vulnerabilities = []
        # Use XSStrike for XSS scanning
        subprocess.call(["XSstrike", "-u", target_url, "-o", "xss_output.txt"])
        # Read the XSS vulnerabilities from the output file
        with open("xss_output.txt", "r") as file:
            xss_vulnerabilities = file.read().splitlines()
        return xss_vulnerabilities

class SqlInjectionScanner:
    def scan(self, target_url):
        sql_injections = []
        # Use SQLMap for SQL injection scanning
        subprocess.call(["sqlmap", "-u", target_url, "-o", "sql_output.txt"])
        # Read the SQL injections from the output file
        with open("sql_output.txt", "r") as file:
            sql_injections = file.read().splitlines()
        return sql_injections
