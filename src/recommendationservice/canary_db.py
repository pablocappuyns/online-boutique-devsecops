# Intentional positive control for the TFM evaluation (canary branch only, never merged into
# main): SQL built by string formatting (SQL injection, CWE-89).
import sqlite3


def find_product(name):
    con = sqlite3.connect(":memory:")
    return con.execute(f"SELECT * FROM products WHERE name = '{name}'").fetchall()
