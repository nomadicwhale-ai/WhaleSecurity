# Fixture for WS-INJ-003. Attack-sample data, not production code.
subprocess.run(["echo", name], shell=False)
subprocess.run( "echo harmless", shell=True)
subprocess.run(r"echo harmless", shell=True)
os.system( "echo harmless")
os.system()
