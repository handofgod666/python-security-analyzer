"""
Examples of VULNERABLE code with SQL injection risks.
DO NOT use these patterns in production!
"""

import psycopg2


def vulnerable_fstring_query(user_id):
    """BAD: Using f-string in SQL query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: f-string with user input
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchall()


def vulnerable_concatenation(username):
    """BAD: String concatenation in SQL query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)

    return cursor.fetchall()


def vulnerable_format_method(email):
    """BAD: Using .format() in SQL query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: .format() with user input
    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    cursor.execute(query)

    return cursor.fetchall()


def vulnerable_percent_formatting(role):
    """BAD: Using % formatting in SQL query."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: % formatting
    query = "SELECT * FROM users WHERE role = '%s'" % role
    cursor.execute(query)

    return cursor.fetchall()


def vulnerable_delete_query(user_id):
    """BAD: DELETE with f-string."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: DELETE with f-string
    query = f"DELETE FROM users WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()


def vulnerable_insert_query(username, password):
    """BAD: INSERT with string concatenation."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: INSERT with concatenation
    query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')"
    cursor.execute(query)
    conn.commit()


def vulnerable_update_query(user_id, new_email):
    """BAD: UPDATE with f-string."""
    conn = psycopg2.connect("dbname=test")
    cursor = conn.cursor()

    # VULNERABLE: UPDATE with f-string
    query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()
