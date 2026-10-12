# Fixture for WS-INJ-001. Attack-sample data, not production code.
cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")  # expect: WS-INJ-001
cursor.execute("SELECT * FROM orders WHERE id = %s" % order_id)  # expect: WS-INJ-001
cursor.execute("SELECT * FROM orders WHERE id = {}".format(order_id))  # expect: WS-INJ-001
cursor.execute("SELECT * FROM orders WHERE id = " + order_id)  # expect: WS-INJ-001
