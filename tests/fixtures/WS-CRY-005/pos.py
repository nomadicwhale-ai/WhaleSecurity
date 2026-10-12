# Fixture for WS-CRY-005. Attack-sample data, not production code.
requests.get("https://api.example.invalid", verify=False)  # expect: WS-CRY-005
ssl._create_unverified_context()  # expect: WS-CRY-005
