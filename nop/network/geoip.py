import urllib.request
import json

def geoip_lookup(ip):
    try:
        # ip-api.com is free, no key required, returns JSON
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        response = urllib.request.urlopen(req, timeout=5)
        data = json.loads(response.read().decode())

        if data.get("status") == "fail":
            return {"ip": ip, "error": data.get("message", "lookup failed")}

        return {
            "ip": ip,
            "data": {
                "country":      data.get("country"),
                "region":       data.get("regionName"),
                "city":         data.get("city"),
                "zip":          data.get("zip"),
                "lat":          data.get("lat"),
                "lon":          data.get("lon"),
                "timezone":     data.get("timezone"),
                "isp":          data.get("isp"),
                "org":          data.get("org"),
                "as":           data.get("as"),
            }
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}