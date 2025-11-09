import re
import urllib.parse
import socket
import warnings

# Suppress the urllib3 warning about LibreSSL
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

import requests
from bs4 import BeautifulSoup
import ssl
import datetime
import whois
import sys

def check_certificate(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                issuer_cn = issuer.get('commonName', '')
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                age_days = (datetime.datetime.now() - not_before).days
                age_years = age_days / 365.25
                trusted_cas = ['GeoTrust', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign']
                is_trusted = any(ca.lower() in issuer_cn.lower() for ca in trusted_cas)
                return is_trusted and age_years >= 1
    except:
        return False

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except:
        return None

def check_domain_age(w):
    if w and w.creation_date:
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            now = datetime.datetime.now()
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_years = (now - creation_date).days / 365.25
            return age_years >= 0.5  # >= 6 months
    return False

def check_domain_length(w):
    if w and w.expiration_date:
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if expiration_date:
            now = datetime.datetime.now()
            if expiration_date.tzinfo is not None:
                expiration_date = expiration_date.replace(tzinfo=None)
            length_years = (expiration_date - now).days / 365.25
            return length_years > 1  # > 1 year left
    return False

def extract_features(url):
    features = [0] * 25  # Initialize with 0 (suspicious)

    # Parse URL
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(':')[0]  # Remove port if present
    path = parsed.path
    query = parsed.query
    full_url = url

    # Feature 1: Using IP Address
    try:
        socket.inet_aton(domain)
        features[0] = -1  # Phishy
    except socket.error:
        features[0] = 1  # Legitimate

    # Feature 2: Long URL
    length = len(full_url)
    if length < 54:
        features[1] = 1
    elif 54 <= length <= 75: 
        features[1] = 0
    else:
        features[1] = -1

    # Feature 3: Shortening Service
    shortening_services = ['tinyurl', 'bit.ly', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
    if any(service in domain.lower() for service in shortening_services):
        features[2] = -1
    else:
        features[2] = 1

    # Feature 4: @ Symbol
    if '@' in full_url:
        features[3] = -1
    else:
        features[3] = 1

    # Feature 5: // Redirection
    last_double_slash = full_url.rfind('//')
    if last_double_slash > 7:
        features[4] = -1
    else:
        features[4] = 1

    # Feature 6: - in Domain
    if '-' in domain:
        features[5] = -1
    else:
        features[5] = 1

    # Feature 7: Subdomains
    dots = domain.count('.')
    if dots == 1:
        features[6] = 1
    elif dots == 2:
        features[6] = 0
    else:
        features[6] = -1

    # Feature 8: HTTPS
    if parsed.scheme == 'https':
        if check_certificate(domain):
            features[7] = 1  # Legitimate
        else:
            features[7] = 0  # Suspicious (not trusted or too new)
    else:
        features[7] = -1  # Phishy

    # Get WHOIS info once
    w = get_domain_info(domain)

    # Feature 9: Domain Registration Length
    if check_domain_length(w):
        features[8] = 1  # Legitimate
    else:
        features[8] = -1  # Phishy

    # Feature 10: Favicon (requires HTML)
    features[9] = 1  # Placeholder, will be updated below

    # Feature 11: Port
    port = parsed.port
    if port and port not in [80, 443]:
        features[10] = -1
    else:
        features[10] = 1

    # Feature 12: HTTPS in Domain
    if 'https' in domain.lower():
        features[11] = -1
    else:
        features[11] = 1

    # For features requiring HTML, try to fetch
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        soup = None

    if soup:
        # Feature 10: Favicon
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        if favicon and favicon.get('href'):
            favicon_href = favicon['href']
            if domain not in favicon_href:
                features[9] = -1  # Phishy
            else:
                features[9] = 1  # Legitimate
        else:
            features[9] = 1  # No favicon, assume legitimate

        # Feature 13: Request URL
        external_objects = 0
        total_objects = 0
        # Check images
        imgs = soup.find_all('img', src=True)
        for img in imgs:
            total_objects += 1
            if domain not in img['src']:
                external_objects += 1
        # Check scripts
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            total_objects += 1
            if domain not in script['src']:
                external_objects += 1
        # Check links (stylesheets)
        links = soup.find_all('link', href=True, rel='stylesheet')
        for link in links:
            total_objects += 1
            if domain not in link['href']:
                external_objects += 1
        # Check videos
        videos = soup.find_all('video', src=True)
        for video in videos:
            total_objects += 1
            if domain not in video['src']:
                external_objects += 1
        # Check audios
        audios = soup.find_all('audio', src=True)
        for audio in audios:
            total_objects += 1
            if domain not in audio['src']:
                external_objects += 1
        if total_objects > 0:
            percent = (external_objects / total_objects) * 100
            if percent < 22:
                features[12] = 1
            elif 22 <= percent <= 61:
                features[12] = 0
            else:
                features[12] = -1
        else:
            features[12] = 1  # No objects, assume legitimate

        # Feature 14: Anchor URL
        anchors = soup.find_all('a', href=True)
        total_anchors = len(anchors)
        suspicious_anchors = 0
        for a in anchors:
            href = a['href']
            if href.startswith('http') and domain not in href:
                suspicious_anchors += 1  # External link
            elif href in ['#', '#content', '#skip'] or 'javascript:void(0)' in href.lower():
                suspicious_anchors += 1  # Invalid link
        if total_anchors > 0:
            percent = (suspicious_anchors / total_anchors) * 100
            if percent < 31:
                features[13] = 1
            elif 31 <= percent <= 67:
                features[13] = 0
            else:
                features[13] = -1
        else:
            features[13] = 1

        # Feature 15: Links in <Meta>, <Script>, <Link>
        total_links = 0
        external_links = 0
        # Meta tags (usually no href, but check if any)
        metas = soup.find_all('meta')
        for meta in metas:
            if meta.get('content') and 'http' in meta['content']:
                total_links += 1
                if domain not in meta['content']:
                    external_links += 1
        # Script tags
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            total_links += 1
            if domain not in script['src']:
                external_links += 1
        # Link tags
        links = soup.find_all('link', href=True)
        for link in links:
            total_links += 1
            if domain not in link['href']:
                external_links += 1
        if total_links > 0:
            percent = (external_links / total_links) * 100
            if percent < 17:
                features[14] = 1
            elif 17 <= percent <= 81:
                features[14] = 0
            else:
                features[14] = -1
        else:
            features[14] = 1

        # Feature 16: SFH
        forms = soup.find_all('form', action=True)
        if forms:
            action = forms[0]['action']
            if action == 'about:blank' or not action:
                features[15] = -1
            elif domain not in action:
                features[15] = 0
            else:
                features[15] = 1
        else:
            features[15] = 1

        # Feature 17: Submit to Email
        if 'mailto:' in str(soup) or 'mail(' in str(soup):
            features[16] = -1
        else:
            features[16] = 1

        # Feature 18: Abnormal URL
        if w and w.domain_name:
            features[17] = 1  # Legitimate
        else:
            features[17] = -1  # Phishy

        # Feature 19: Website Forwarding
        redirects = response.history
        num_redirects = len(redirects)
        if num_redirects <= 1:
            features[18] = 1
        elif 2 <= num_redirects < 4:
            features[18] = 0
        else:
            features[18] = -1

        # Feature 20: Status Bar Customization
        if 'onmouseover' in str(soup).lower() and 'status' in str(soup).lower():
            features[19] = -1
        else:
            features[19] = 1

        # Feature 21: Disable Right Click
        if 'event.button==2' in str(soup) or 'oncontextmenu' in str(soup).lower():
            features[20] = -1
        else:
            features[20] = 1

        # Feature 22: Pop-up Window
        if 'window.open' in str(soup) and 'input' in str(soup).lower():
            features[21] = -1
        else:
            features[21] = 1

        # Feature 23: IFrame Redirection
        iframe = soup.find('iframe')
        if iframe:
            frameborder = iframe.get('frameborder')
            style = iframe.get('style', '').lower()
            if frameborder == '0' or ('border' in style and 'none' in style):
                features[22] = -1  # Invisible iframe, phishy
            else:
                features[22] = 1  # Visible iframe, assume legitimate
        else:
            features[22] = 1

    # Features 24-29: Domain based
    # Feature 24: Age of Domain
    if check_domain_age(w):
        features[23] = 1  # Legitimate
    else:
        features[23] = -1  # Phishy

    # Feature 25: DNS Record
    try:
        socket.gethostbyname(domain)
        features[24] = 1  # Legitimate
    except socket.gaierror:
        features[24] = -1  # Phishy



    return features