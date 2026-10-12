# Fixture for WS-CRY-005. Attack-sample data, not production code.
requests.get("https://api.example.invalid", verify=True)
requests.get(url, verify="/etc/ssl/certs/corp-ca.pem")
jwt.decode(token, verify=False)
