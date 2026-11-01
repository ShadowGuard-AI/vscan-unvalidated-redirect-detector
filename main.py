import argparse
import requests
from bs4 import BeautifulSoup
import logging
import sys
import urllib.parse
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_REDIRECT_HOPS = 5
INPUT_TEST_VALUE = "http://redirect-test.example/SENTINEL-INPUT-TARGET"


def _host_is_allowed(hostname, base_url, safe_domains):
    """True when hostname matches the base host or a listed safe domain.

    The comparison is on parsed hostnames: exact match, or a true
    subdomain of a listed safe domain. A substring match never counts.
    """
    if not hostname:
        return False
    hostname = hostname.lower()
    if base_url:
        base_host = urllib.parse.urlparse(base_url).hostname
        if base_host and hostname == base_host.lower():
            return True
    if safe_domains:
        for domain in safe_domains.split(','):
            domain = domain.strip().lower()
            if not domain:
                continue
            if hostname == domain or hostname.endswith('.' + domain):
                return True
    return False


def is_url_safe(url, base_url=None, safe_domains=None):
    """
    Decide whether a redirect target stays inside the allowed scope.

    A target is safe only when it uses http or https and its parsed
    hostname matches the base URL host or a listed safe domain.
    Targets on any other host are the findings this tool reports.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            return False  # Block non-HTTP(S) schemes like file:// or data://
        if base_url is None and not safe_domains:
            return True
        return _host_is_allowed(parsed_url.hostname, base_url, safe_domains)
    except Exception:
        return False


def _origin(url):
    parsed = urllib.parse.urlparse(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == 'https' else 80
    return (parsed.scheme, (parsed.hostname or '').lower(), port)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detect unvalidated redirect vulnerabilities.')
    parser.add_argument('url', help='The URL to scan.')
    parser.add_argument('--input-param', dest='input_param', help='The URL parameter name that might control the redirect (optional).', default=None)
    parser.add_argument('--safe-domains', dest='safe_domains', help='Comma-separated list of safe domains to allow (optional).', default=None)
    parser.add_argument('--method', dest='method', choices=['GET', 'POST'], default='GET', help='HTTP method to use (default: GET).')
    parser.add_argument('--data', dest='data', help='Data to send with the request (for POST method, e.g., "param1=value1&param2=value2").', default=None)

    return parser


def analyze_html(html_content, base_url, input_param=None, safe_domains=None):
    """
    Analyzes HTML content for redirect-related tags and attributes.

    Only candidates that fail the safety check are reported: a target
    whose parsed hostname is neither the base host nor a listed safe
    domain, or whose scheme is not http or https. Same host targets
    are not findings. The input_param argument no longer flags a page
    by itself; user input control is tested by an actual request in
    main, not by parameter presence in this parse.

    Returns:
        list: A list of potential unvalidated redirect URLs.
    """

    redirect_urls = []

    def consider(url):
        absolute_url = urllib.parse.urljoin(base_url, url)
        if not is_url_safe(absolute_url, base_url, safe_domains):
            if absolute_url not in redirect_urls:
                redirect_urls.append(absolute_url)

    soup = BeautifulSoup(html_content, 'html.parser')

    # Check for <meta http-equiv="refresh" content="0; URL='...'">
    for meta_tag in soup.find_all('meta', attrs={'http-equiv': re.compile(r"refresh", re.IGNORECASE)}):
        if 'content' in meta_tag.attrs:
            content = meta_tag['content']
            match = re.search(r"URL=['\"]?([^'\"]+)['\"]?", content, re.IGNORECASE)
            if match:
                consider(match.group(1))

    # Check for window.location.href redirects in JavaScript
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            script_content = script_tag.string
            matches = re.findall(r"window\.location\.href\s*=\s*[\"']?([^\"']+)[\"']?", script_content, re.IGNORECASE)
            for url in matches:
                consider(url)

    # Check for <a href="..."> redirects (less likely to be vulnerable, but worth checking)
    for a_tag in soup.find_all('a', href=True):
        consider(a_tag['href'])

    return redirect_urls


def fetch_reporting_redirects(url, method, headers, post_data=None):
    """
    Fetch url without automatic redirect following.

    Each redirect hop is inspected. A hop that stays inside the named
    target origin (scheme, host, and port of the URL the operator
    supplied) is followed explicitly and logged. A hop that leaves
    that origin is reported as a finding and is not followed.

    Returns:
        (response, findings): the final response received, and a list
        of out of scope redirect targets that were reported, not fetched.
    """
    findings = []
    current_url = url
    current_method = method
    for _ in range(MAX_REDIRECT_HOPS + 1):
        if current_method == 'POST':
            response = requests.post(current_url, headers=headers, data=post_data, timeout=10, allow_redirects=False)
        else:
            response = requests.get(current_url, headers=headers, timeout=10, allow_redirects=False)
        if response.status_code not in REDIRECT_STATUSES:
            return response, findings
        location = response.headers.get('Location')
        if not location:
            return response, findings
        target = urllib.parse.urljoin(current_url, location)
        if _origin(target) == _origin(url):
            logging.info(f"Redirect within the named target scope: {current_url} -> {target}")
            current_url = target
            if response.status_code == 303:
                current_method = 'GET'
            continue
        logging.warning(f"Open redirect: {current_url} redirects to {target}, outside the named target scope. Target not followed.")
        findings.append(target)
        return response, findings
    logging.warning(f"Redirect chain exceeded {MAX_REDIRECT_HOPS} hops at {current_url}; chain not followed further.")
    findings.append(current_url)
    return response, findings


def test_input_param(url, input_param, headers):
    """
    Test whether user input controls the redirect destination.

    Sends one request with a distinctive test value in the named
    parameter and compares the redirect target with that value.

    Returns:
        str or None: the redirect target when the supplied value
        controls it, otherwise None.
    """
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[input_param] = INPUT_TEST_VALUE
    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
    if response.status_code not in REDIRECT_STATUSES:
        return None
    location = response.headers.get('Location')
    if not location:
        return None
    target = urllib.parse.urljoin(test_url, location)
    if INPUT_TEST_VALUE in target:
        return target
    return None


def main():
    """
    Main function to execute the vulnerability scanner.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    url = args.url
    input_param = args.input_param
    safe_domains = args.safe_domains
    method = args.method
    data = args.data

    try:
        # Input validation (example: URL scheme check)
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme:
            raise ValueError("Invalid URL: Missing scheme (e.g., http:// or https://)")

        # Make the HTTP request, inspecting redirects instead of
        # silently following them.
        headers = {'User-Agent': 'vscan-unvalidated-redirect-detector/1.0'} # Mimic a browser
        post_data = None
        if method == 'POST' and data:
            # parse_qsl splits each field on the first = only, so a
            # value containing = is kept whole instead of crashing.
            post_data = dict(urllib.parse.parse_qsl(data, keep_blank_values=True))

        response, redirect_findings = fetch_reporting_redirects(url, method, headers, post_data)

        if response.status_code >= 400:
            logging.error(f"Scan failed: {url} returned HTTP {response.status_code}; no completed scan to report.")
            sys.exit(1)

        redirect_urls = list(redirect_findings)

        # Analyze the HTML content when a page body was received.
        if response.text:
            for found in analyze_html(response.text, url, input_param, safe_domains):
                if found not in redirect_urls:
                    redirect_urls.append(found)

        # Test user input control with an actual test value.
        if input_param:
            controlled = test_input_param(url, input_param, headers)
            if controlled:
                logging.warning(f"Parameter '{input_param}' controls the redirect destination: the target redirects to the supplied value {controlled}")
                if controlled not in redirect_urls:
                    redirect_urls.append(controlled)

        if redirect_urls:
            logging.warning("Potential unvalidated redirect vulnerabilities found:")
            for redirect_url in redirect_urls:
                logging.warning(f"  - {redirect_url}")
        else:
            logging.info("No potential unvalidated redirect vulnerabilities found.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"Input error: {e}")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
