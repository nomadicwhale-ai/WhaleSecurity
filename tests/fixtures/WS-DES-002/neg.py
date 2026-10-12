# Fixture for WS-DES-002. Attack-sample data, not production code.
yaml.safe_load(request.data)
yaml.load(data, Loader=yaml.SafeLoader)
yaml.load(data, yaml.CSafeLoader)
yaml.load_all(data, Loader=BaseLoader)
YAML(typ="safe")
