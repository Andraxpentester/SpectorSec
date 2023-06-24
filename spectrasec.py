import os
import time
from getpass import getpass
from hashlib import sha256
from bs4 import BeautifulSoup
import requests
import validators
from scanners import SubdomainScanner, NmapScanner, XssScanner, SqlInjectionScanner
from report import generate_report

class SpectraSec:
    def __init__(self):
        self.output_folder = "output"
        self.target_url = ""
        self.subdomain_scanner = SubdomainScanner()
        self.nmap_scanner = NmapScanner()
        self.xss_scanner = XssScanner()
        self.sql_injection_scanner = SqlInjectionScanner()

    def print_with_delay(self, text, delay=0.05):
        for char in text:
            print(char, end="", flush=True)
            time.sleep(delay)
        print()

    def display_logo(self):
        logo = """
         █████╗ ██████╗ ██╗   ██╗██████╗ ██╗     ██╗ █████╗ ███╗   ██╗
        ██╔══██╗██╔══██╗██║   ██║██╔══██╗██║     ██║██╔══██╗████╗  ██║
        ███████║██████╔╝██║   ██║██████╔╝██║     ██║███████║██╔██╗ ██║
        ██╔══██║██╔═══╝ ██║   ██║██╔═══╝ ██║     ██║██╔══██║██║╚██╗██║
        ██║  ██║██║     ╚██████╔╝██║     ███████╗██║██║  ██║██║ ╚████║
        ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝     ╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
        
                          [ SpectraSec v1 - Bug Hunting Tool ]
        """
        self.print_with_delay(logo)

    def display_about_author(self):
        about_lines = [
            "Author: John Doe",
            "Nickname: BugHunter",
            "Experienced bug hunter",
            "Ethical hacker",
            "Security enthusiast",
            "Follow me on GitHub: github.com/bughunter",
        ]

        for line in about_lines:
            self.print_with_delay(line)
            time.sleep(1)
            os.system('clear' if os.name == 'posix' else 'cls')

    def authenticate_user(self):
        print("Please enter your credentials to proceed.")
        username = getpass("Enter username: ")
        password = getpass("Enter password: ")

        username_hash = sha256(username.encode()).hexdigest()
        password_hash = sha256(password.encode()).hexdigest()

        expected_username_hash = "e55313a5bfab3857172a6a32043c15bce2dc9d99eb79d319d42bf39c862ccdbd"
        expected_password_hash = "353e057b897f974eb7175150a528367e9dec1a7fcbb0b5f88b67f5b6108775d7"

        if username_hash == expected_username_hash and password_hash == expected_password_hash:
            print("Authentication successful!")
            time.sleep(1)
            os.system('clear' if os.name == 'posix' else 'cls')
            return True
        else:
            print("Invalid username or password.")
            return False

    def input_target_url(self):
        while True:
            self.target_url = input("Enter the website URL to analyze (or 'exit' to quit): ")
            if self.target_url.lower() == "exit":
                break

            if not self.target_url.startswith("http://") and not self.target_url.startswith("https://"):
                self.target_url = "https://" + self.target_url

            if validators.url(self.target_url):
                if not os.path.exists(self.output_folder):
                    os.makedirs(self.output_folder)
                self.run_scanners()
            else:
                print("Invalid URL. Please enter a valid website URL.")

    def run_scanners(self):
        self.display_logo()

        # Phase 1: Subdomain Enumeration
        subdomains = self.subdomain_scanner.scan(self.target_url)
        print("Subdomains found:", subdomains)

        # Phase 2: Port Scanning and Service Detection
        open_ports = self.nmap_scanner.scan(self.target_url)
        print("Open ports found:", open_ports)

        # Phase 3: Cross-Site Scripting (XSS) Testing
        xss_vulnerabilities = self.xss_scanner.scan(self.target_url)
        print("XSS vulnerabilities found:", xss_vulnerabilities)

        # Phase 4: SQL Injection Testing
        sql_injections = self.sql_injection_scanner.scan(self.target_url)
        print("SQL injections found:", sql_injections)

        # Generate comprehensive report
        report_data = {
            "Target URL": self.target_url,
            "Subdomains": subdomains,
            "Open Ports": open_ports,
            "XSS Vulnerabilities": xss_vulnerabilities,
            "SQL Injections": sql_injections
        }
        comprehensive_report = generate_report(report_data)

        # Save report to a file
        with open(os.path.join(self.output_folder, "report.txt"), "w") as file:
            file.write(comprehensive_report)

        print("Scans are complete. The report has been saved to 'output/report.txt'.")

    def start(self):
        if self.authenticate_user():
            self.input_target_url()
        self.display_about_author()

if __name__ == "__main__":
    spectra_sec = SpectraSec()
    spectra_sec.start()
