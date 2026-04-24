import whois

# fields we care about — whois returns a lot of noise
FIELDS = [
    "domain_name", "registrar", "creation_date",
    "expiration_date", "updated_date", "name_servers",
    "status", "emails", "org", "country"
]

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        result = {}

        for field in FIELDS:
            value = getattr(w, field, None)
            if value is None:
                continue
            # whois sometimes returns lists with duplicates — clean them up
            if isinstance(value, list):
                # deduplicate and convert to strings
                seen = set()
                cleaned = []
                for v in value:
                    s = str(v).strip()
                    if s not in seen:
                        seen.add(s)
                        cleaned.append(s)
                value = cleaned
            else:
                value = str(value).strip()
            result[field] = value

        if not result:
            return {"domain": domain, "error": "no whois data found"}

        return {"domain": domain, "data": result}

    except whois.parser.PywhoisError as e:
        return {"domain": domain, "error": str(e)}
    except Exception as e:
        return {"domain": domain, "error": str(e)}