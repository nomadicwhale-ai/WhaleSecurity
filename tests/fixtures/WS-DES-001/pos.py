# Fixture for WS-DES-001. Attack-sample data, not production code.
pickle.loads(request.data)  # expect: WS-DES-001
joblib.load(stream)  # expect: WS-DES-001
torch.load(path, weights_only=False)  # expect: WS-DES-001
