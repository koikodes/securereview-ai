query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))