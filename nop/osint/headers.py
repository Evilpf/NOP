import urllib.request
import urllib.error

# headers that reveal useful info about the target
INTERESTING = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-wp-cf-super-cache", "via",
    "x-backend-server", "x-served-by", "x-cache", "cf-ray", "x-amz-cf-id"
]

# security headers we want to check for — missing ones are a finding
SECURITY = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy"
]

def get_headers(url, timeout=5):
    # add scheme if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        response = urllib.request.urlopen(req, timeout=timeout)
        headers = dict(response.headers)
        # normalize keys to lowercase for consistent lookups
        headers = {k.lower(): v for k, v in headers.items()}
        return _parse_headers(url, headers)
    except urllib.error.HTTPError as e:
        # still grab headers even on error responses like 403, 404
        headers = dict(e.headers)
        headers = {k.lower(): v for k, v in headers.items()}
        return _parse_headers(url, headers, status=e.code)
    except Exception as e:
        return {"url": url, "error": str(e)}

def _parse_headers(url, headers, status=200):
    # pull out the interesting tech stack headers
    tech = {k: headers[k] for k in INTERESTING if k in headers}

    # check which security headers are present vs missing
    security = {}
    for h in SECURITY:
        if h in headers:
            security[h] = {"present": True, "value": headers[h]}
        else:
            security[h] = {"present": False}

    return {
        "url": url,
        "status": status,
        "tech": tech,
        "security": security,
        "all": headers
    }