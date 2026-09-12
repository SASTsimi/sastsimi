from __future__ import annotations

import json
import sqlite3
import sys


def lookup(username: str) -> list[str]:
    """Deliberately unsafe SQL construction used only by the Docker E2E."""

    database = sqlite3.connect(":memory:")
    database.executescript(
        """
        CREATE TABLE users (username TEXT, role TEXT);
        INSERT INTO users VALUES ('guest', 'user');
        INSERT INTO users VALUES ('administrator', 'admin');
        """
    )
    query = f"SELECT role FROM users WHERE username = '{username}'"
    return [row[0] for row in database.execute(query)]


if __name__ == "__main__":
    print(json.dumps(lookup(sys.argv[1])))
