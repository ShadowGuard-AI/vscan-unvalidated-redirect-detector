import argparse
import requests
from bs4 import BeautifulSoup
import logging
import urllib.parse
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_url_safe(url):
    """
    Basic check to prevent redirects to potentially harmful protocols or domains.
    This is a simplified example and should be expanded for real-world use.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            return False  # Block non-HTTP(S) schemes like file:// or data://
        
        # Example: Block specific domains (replace with your blacklist)
        # blocked_domains = ["example.com", "evil.com"]
        # if parsed_url.netloc in blocked_domains:
        #     return False

        return True
    except:
        return False

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

    Args:
        html_content (str): The HTML content to analyze.
        base_url (str): The base URL of the page.
        input_param (str): The URL parameter that might control the redirect.
        safe_domains (str): Comma-separated string of safe domains allowed

    Returns:
        list: A list of potential unvalidated redirect URLs.
    """

    redirect_urls = []
    soup = BeautifulSoup(html_content, 'html.parser')

    # Check for <meta http-equiv="refresh" content="0; URL='...'">
    for meta_tag in soup.find_all('meta', attrs={'http-equiv': re.compile(r"refresh", re.IGNORECASE)}):
        if 'content' in meta_tag.attrs:
            content = meta_tag['content']
            match = re.search(r"URL=['\"]?([^'\"]+)['\"]?", content, re.IGNORECASE)
            if match:
                url = match.group(1)
                absolute_url = urllib.parse.urljoin(base_url, url)
                if input_param:
                     #  Potentially vulnerable to user-supplied input
                    redirect_urls.append(absolute_url)
                elif is_url_safe(absolute_url):
                    if safe_domains:
                        is_safe = False
                        for domain in safe_domains.split(','):
                            parsed_url = urllib.parse.urlparse(absolute_url)
                            if domain in parsed_url.netloc:
                                is_safe = True
                                break
                        if not is_safe:
                             redirect_urls.append(absolute_url)
                    else:
                        redirect_urls.append(absolute_url)

                else:
                    redirect_urls.append(absolute_url)
                
    # Check for window.location.href redirects in JavaScript
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            script_content = script_tag.string
            matches = re.findall(r"window\.location\.href\s*=\s*[\"']?([^\"']+)[\"']?", script_content, re.IGNORECASE)
            for url in matches:
                absolute_url = urllib.parse.urljoin(base_url, url)
                if input_param:
                    # Potentially vulnerable to user-supplied input
                    redirect_urls.append(absolute_url)
                elif is_url_safe(absolute_url):
                    if safe_domains:
                        is_safe = False
                        for domain in safe_domains.split(','):
                            parsed_url = urllib.parse.urlparse(absolute_url)
                            if domain in parsed_url.netloc:
                                is_safe = True
                                break
                        if not is_safe:
                             redirect_urls.append(absolute_url)
                    else:
                        redirect_urls.append(absolute_url)
                else:
                    redirect_urls.append(absolute_url)

    # Check for <a href="..."> redirects (less likely to be vulnerable, but worth checking)
    for a_tag in soup.find_all('a', href=True):
        url = a_tag['href']
        absolute_url = urllib.parse.urljoin(base_url, url)
        if input_param:
             # Potentially vulnerable to user-supplied input
            redirect_urls.append(absolute_url)
        elif is_url_safe(absolute_url):
            if safe_domains:
                is_safe = False
                for domain in safe_domains.split(','):
                    parsed_url = urllib.parse.urlparse(absolute_url)
                    if domain in parsed_url.netloc:
                        is_safe = True
                        break
                if not is_safe:
                     redirect_urls.append(absolute_url)
            else:
                redirect_urls.append(absolute_url)
        else:
            redirect_urls.append(absolute_url)

    return redirect_urls


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

        # Make the HTTP request
        headers = {'User-Agent': 'vscan-unvalidated-redirect-detector/1.0'} # Mimic a browser
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method == 'POST':
            if data:
                post_data = {}
                for item in data.split('&'):
                   key, value = item.split('=')
                   post_data[key] = value
                response = requests.post(url, headers=headers, data=post_data, timeout=10)
            else:
                 response = requests.post(url, headers=headers, timeout=10) # Empty post
        else:
            raise ValueError("Invalid HTTP method.")


        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Analyze the HTML content
        redirect_urls = analyze_html(response.text, url, input_param, safe_domains)

        if redirect_urls:
            logging.warning("Potential unvalidated redirect vulnerabilities found:")
            for redirect_url in redirect_urls:
                logging.warning(f"  - {redirect_url}")
        else:
            logging.info("No potential unvalidated redirect vulnerabilities found.")

    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
    except ValueError as e:
        logging.error(f"Input error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()