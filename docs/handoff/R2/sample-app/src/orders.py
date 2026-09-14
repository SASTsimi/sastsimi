import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("orders.db")


@app.route('/orders/<id>')
def get_order(id):
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE id = '" + id + "'"
    cursor.execute(query)
    row = cursor.fetchone()
    return str(row)


@app.route('/orders/<id>/safe')
def get_order_safe(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE id = ?", (id,))
    row = cursor.fetchone()
    return str(row)
