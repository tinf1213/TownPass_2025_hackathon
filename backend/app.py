import asyncio
import time
import random
from flask import Flask, request, jsonify
import whois  
from urllib.parse import urlparse  
from datetime import datetime 
import pytz
import parse
import joblib
import requests
import socket
import ipaddress
import geocoder
import redis
import json

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, db=0)
# --- Your Test Functions ---
# These are async functions. We use asyncio.sleep to simulate
# a network call (like to an external API or a database).

async def check_phishing_db(url: str) -> dict:
    """Simulates checking a URL against a phishing database."""
    print(f"START: check_phishing_db for {url}")
    # Simulate network delay
    await asyncio.sleep(random.uniform(0.5, 1.5))
    
    is_fraud = "example.com" in url # Simple mock logic
    print(f"END: check_phishing_db for {url}")
    
    return {
        "test_name": "phishing_database",
        "test_result": "URL found in DB" if is_fraud else "URL clear",
        "is_fraud": is_fraud
    }

async def analyze_content_keywords(url: str) -> dict:
    """Simulates downloading and scanning page content for keywords."""
    print(f"START: analyze_content_keywords for {url}")
    # Simulate network delay for download + analysis
    await asyncio.sleep(random.uniform(1.0, 2.0))
    
    is_fraud = "bad-stuff.com" in url # Simple mock logic
    print(f"END: analyze_content_keywords for {url}")
    
    return {
        "test_name": "content_analysis",
        "test_result": "Fraudulent keywords found",
        "is_fraud": is_fraud
    }

def _get_whois_data(domain: str) -> dict:
    """
    This is a BLOCKING function that runs the WHOIS query.
    We will run this in a thread to not block the async app.
    """
    try:
        # This one call gets all the data we need
        w = whois.whois(domain)

        # Handle empty results (some domains don't return data)
        if not w.creation_date:
            return {"country": None, "creation_date": None, "error": "No WHOIS data found"}

        # Data can be a list or a single value, so we normalize it
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]  # Get the first (oldest) date

        country = w.country
        if isinstance(country, list):
            country = country[0]  # Get the first listed country

        return {"country": country, "creation_date": creation_date, "error": None}
    
    except Exception as e:
        # Catch errors like 'domain not found' or network issues
        return {"country": None, "creation_date": None, "error": str(e)}

def check_domain_info(url: str) -> dict:
    """
    Checks domain registration date (age) and country via WHOIS.
    """
    print(f"START: check_domain_info for {url}")
    
    try:
        # 1. Extract the domain from the full URL
        # e.g., "http://www.google.com/search" -> "google.com"
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if not domain:
            raise ValueError("Could not parse domain from URL")
        
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
    except Exception as e:
        return {
            "test_result": f"Invalid URL format: {e}",
            "is_fraud": True,
            "is_gov": False,
            "is_edu": False
        }

    # 2. Run the blocking WHOIS query in a separate thread
    # This is the correct way to do this in asyncio
    whois_data = _get_whois_data(domain)
    print(whois_data)
    is_gov = False
    if domain.endswith("gov.tw") or domain.endswith("gov.taipei"):
        is_gov = True
        
    is_edu = False
    if domain.endswith("edu.tw"):
        is_edu = True

    print(f"END: check_domain_info for {domain}")
    
    # 3. Handle errors from the WHOIS lookup
    if whois_data["error"]:
        if is_gov or is_edu:
            is_fraud = False
        else:
            is_fraud = True
        return {
            "test_result": f"WHOIS error: {whois_data['error']}",
            "is_fraud": is_fraud,
            "is_gov": is_gov,
            "is_edu": is_edu
        }

    # 4. Format the result and determine fraud status
    is_fraud = False
    result_parts = []
    
    if whois_data["country"]:
        result_parts.append(f"Country: {whois_data['country']}")
    
    if whois_data["creation_date"]:
        creation_date = whois_data["creation_date"]
        now = datetime.now()
        now = now.replace(tzinfo=pytz.timezone('UTC'))
        domain_age_days = (now - creation_date).days
        
        result_parts.append(f"Created: {creation_date.strftime('%Y-%m-%d')} ({domain_age_days} days old)")
        
        # **Fraud Logic: Mark as fraud if domain is less than 90 days old**
        if domain_age_days < 180:
            is_fraud = True
    else:
        # No creation date is a red flag
        is_fraud = True
        result_parts.append("No creation date found.")

    return {
        "test_result": {
            "Country": whois_data['country'],
            "Created": whois_data['creation_date'].strftime('%Y-%m-%d'),
            "Domain_age": domain_age_days/30
        },
        "is_fraud": is_fraud,
        "is_gov": is_gov,
        "is_edu": is_edu
    }

async def ml_testing(sample):
    model = joblib.load("phishing_model.joblib")
    # sample = [[1, 0, 1, -1, 1, -1, 0, 1, 1, -1, ...], ...]  # 多筆測資
    y_probe = model.predict_proba(sample)   # y_probe = [[probe_of_-1, probe_of_1], ...]
    y_pred = model.predict(sample)          # y_pred  = [pred, ...]
    return y_probe

async def thirdparty_testing(url):
    # The URL for the API endpoint
    api_url = "https://link-checker.nordvpn.com/v1/public-url-checker/check-url"

    # The data to send in the request body
    payload = {
        "url": url
    }

    # Send the POST request with the JSON payload
    response = requests.post(api_url, json=payload)
    return response.json()

async def ip_location_testing(url):
    parsed_url = urlparse(url)
    hostname = str(parsed_url.hostname)
    ip_address = socket.gethostbyname(hostname)
    g_ip = geocoder.ip(ip_address)
    return g_ip.country, ip_address

def is_redis_connected(r: redis.Redis) -> bool:
    try:
        return r.ping()
    except redis.ConnectionError:
        return False
    
def fetch_cache(url):
    # 1️⃣ 先查 Redis cache
    if is_redis_connected(r) == False:
        return None
    cached = r.get(url)
    if cached:
        print("✅ 使用快取資料")
        return json.loads(cached)
    else:
        return None
    
def save_cache(key, value):
    # 設定快取有效期限 (例如 1 小時)
    r.setex(key, 3600, json.dumps(value))
    return True

# --- The API Endpoint ---

@app.route('/test_url', methods=['POST'])
async def test_url():
    """
    Receives a URL, runs all fraud tests in parallel,
    and returns a list of results.
    """
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    url_to_test = data['url']

    print(f'check cache for {url_to_test}')
    results = fetch_cache(url_to_test)
    if results == None:
        print('cache not found')
    else:
        print('cache found')
        return (results), 200
    
    print(f"--- Firing tests for {url_to_test} ---")
    results = []
    start_time = time.time()

    thirdparty_testing_result = await thirdparty_testing(url_to_test)

    if thirdparty_testing_result["category"] == 1:
        results.append({"nordVPN":"safe"})
    else:
        results.append({"nordVPN":"unsafe"})
    features = parse.extract_features(url_to_test)
    ml_result = await ml_testing([features])
    if ml_result[0][0] >= 0.5:
        results.append({"MLtest":"unsafe"})
    else:
        results.append({"MLtest":"safe"})

    info_result = check_domain_info(url_to_test)
    results.append(info_result)


    server_country, ip_address = await ip_location_testing(url_to_test)
    if ipaddress.ip_address(ip_address):
        results.append({"ServerLocation": server_country})
    else:
        results.append({"ServerLocation": "fail to get an ip"})

    
    
    # results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    print(f"--- All tests completed in {end_time - start_time:.2f} seconds ---")

    if save_cache(url_to_test, results) == False:
        print('save cache failed')
    else:
        print('save cache success')

    return (results), 200
    # return jsonify({}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)