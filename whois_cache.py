import json, os
import whois

CACHE_FILE = "whois_cache.json"

# Load existing cache safely
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)
    except json.JSONDecodeError:
        cache = {}
else:
    cache = {}

def cached_whois(domain):
    domain = domain.lower().strip()

    # Return from cache if available
    if domain in cache:
        return cache[domain]

    # Run actual WHOIS
    try:
        result = whois.whois(domain)
        cache[domain] = result
    except:
        cache[domain] = {}

    # Save to file
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, default=str)

    return cache[domain]
