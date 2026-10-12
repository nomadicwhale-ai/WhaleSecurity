# Fixture for WS-DES-002. Attack-sample data, not production code.
yaml.load(request.data)  # expect: WS-DES-002
yaml.load(data, Loader=yaml.Loader)  # expect: WS-DES-002
yaml.unsafe_load(data)  # expect: WS-DES-002
