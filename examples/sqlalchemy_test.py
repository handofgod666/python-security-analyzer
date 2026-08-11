"""
Examples of SQLAlchemy usage patterns for testing.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session


def vulnerable_raw_sql():
    """VULNERABLE: Using text() with user input."""
    user_id = input("Enter user ID: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # VULNERABLE: Direct string interpolation in text()
        query = text(f"SELECT * FROM users WHERE id = {user_id}")
        result = session.execute(query)


def vulnerable_raw_concatenation():
    """VULNERABLE: String concatenation with text()."""
    username = input("Enter username: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # VULNERABLE: String concatenation
        query = text("SELECT * FROM users WHERE username = '" + username + "'")
        result = session.execute(query)


def vulnerable_format():
    """VULNERABLE: Using .format() with text()."""
    email = input("Enter email: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # VULNERABLE: .format() method
        query = text("SELECT * FROM users WHERE email = '{}'".format(email))
        result = session.execute(query)


def safe_bound_parameters():
    """SAFE: Using bound parameters."""
    user_id = input("Enter user ID: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # SAFE: Bound parameters
        query = text("SELECT * FROM users WHERE id = :user_id")
        result = session.execute(query, {"user_id": user_id})


def safe_orm_query():
    """SAFE: Using ORM without raw SQL."""
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = 'users'
        id: Mapped[int] = mapped_column(primary_key=True)
        username: Mapped[str]

    username = input("Enter username: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # SAFE: ORM query with filter
        result = session.query(User).filter(User.username == username).all()


def vulnerable_execute_string():
    """VULNERABLE: Direct execute with f-string."""
    table_name = input("Enter table name: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # VULNERABLE: f-string in execute
        result = session.execute(f"SELECT * FROM {table_name}")


def safe_execute_with_params():
    """SAFE: execute with parameters."""
    user_id = input("Enter user ID: ")

    engine = create_engine('sqlite:///database.db')
    with Session(engine) as session:
        # SAFE: Using parameters
        result = session.execute(
            text("SELECT * FROM users WHERE id = :id"),
            {"id": user_id}
        )
