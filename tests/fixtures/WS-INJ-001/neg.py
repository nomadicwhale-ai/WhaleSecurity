# Fixture for WS-INJ-001. Attack-sample data, not production code.
cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
cursor.execute(f"SELECT 1")
cursor.execute(sql.SQL("SELECT * FROM {}").format(sql.Identifier(table)))
logger.execute(f"status {order_id}")
