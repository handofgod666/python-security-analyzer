"""
Examples demonstrating data flow analysis capabilities.
"""

import sqlite3


def vulnerable_user_input():
    """Example: Direct user input in SQL query."""
    user_id = input("Enter user ID: ")

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # VULNERABLE: user_id comes from input()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)


def vulnerable_request_data():
    """Example: Flask request data in SQL."""
    from flask import request

    username = request.args.get('username')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # VULNERABLE: username comes from request.args
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")


def vulnerable_propagation():
    """Example: Taint propagation through variables."""
    user_input = input("Enter search term: ")
    search_term = user_input  # Taint propagates
    final_term = search_term  # Still tainted

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # VULNERABLE: final_term is tainted from user_input
    query = f"SELECT * FROM products WHERE name LIKE '%{final_term}%'"
    cursor.execute(query)


def safe_parameterized():
    """Example: Safe parameterized query."""
    user_id = input("Enter user ID: ")

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # SAFE: Using parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def safe_constant():
    """Example: Safe because data is constant."""
    table_name = "users"  # Not tainted - constant

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # SAFE: table_name is a constant
    query = f"SELECT * FROM {table_name}"
    cursor.execute(query)
