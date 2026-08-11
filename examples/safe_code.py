"""
Examples of SAFE code - best practices for SQL queries.
"""

import psycopg2


def safe_parameterized_query(user_id):
    """GOOD: Using parameterized query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # SAFE: parameterized query
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))

    return cursor.fetchall()


def safe_named_parameters(username, email):
    """GOOD: Using named parameters."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # SAFE: named parameters
    query = "SELECT * FROM users WHERE username = %(username)s AND email = %(email)s"
    cursor.execute(query, {'username': username, 'email': email})

    return cursor.fetchall()


def safe_insert_query(username, password):
    """GOOD: INSERT with parameterized query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # SAFE: parameterized INSERT
    query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    cursor.execute(query, (username, password))
    conn.commit()


def safe_update_query(user_id, new_email):
    """GOOD: UPDATE with parameterized query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # SAFE: parameterized UPDATE
    query = "UPDATE users SET email = %s WHERE id = %s"
    cursor.execute(query, (new_email, user_id))
    conn.commit()


def safe_delete_query(user_id):
    """GOOD: DELETE with parameterized query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # SAFE: parameterized DELETE
    query = "DELETE FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    conn.commit()
