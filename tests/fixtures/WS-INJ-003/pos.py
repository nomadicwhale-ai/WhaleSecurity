# Fixture for WS-INJ-003. Attack-sample data, not production code.
subprocess.run(request.args["command"], shell=True)  # expect: WS-INJ-003
subprocess.check_output(f"echo {name}", shell=True)  # expect: WS-INJ-003
os.system(command)  # expect: WS-INJ-003
