import ssl
import socket
import datetime

def get_ssl_info(host, port=443, timeout=5):
    try:
        # create a default SSL context — verifies certs by default
        ctx = ssl.create_default_context()

        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=timeout),
            server_hostname=host
        ) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

        # pull subject fields into a flat dict
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        # parse expiry dates
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        days_left = (not_after - now).days

        # SANs — Subject Alternative Names, all the domains the cert covers
        sans = []
        for entry in cert.get("subjectAltName", []):
            if entry[0] == "DNS":
                sans.append(entry[1])

        return {
            "host": host,
            "port": port,
            "subject": subject.get("commonName"),
            "issuer": issuer.get("organizationName"),
            "valid_from": not_before.strftime("%Y-%m-%d"),
            "valid_until": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "expired": days_left < 0,
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "sans": sans
        }

    except ssl.SSLCertVerificationError as e:
        return {"host": host, "port": port, "error": f"cert verification failed: {e}"}
    except ssl.SSLError as e:
        return {"host": host, "port": port, "error": f"SSL error: {e}"}
    except ConnectionRefusedError:
        return {"host": host, "port": port, "error": "connection refused"}
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}