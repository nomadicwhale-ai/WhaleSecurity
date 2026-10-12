# Fixture for WS-INJ-009. Attack-sample data, not production code.
eval(request.args["expression"])  # expect: WS-INJ-009
exec(request.data)  # expect: WS-INJ-009
