# database.py
import sqlite3
from sqlite3 import Error
import os

DB_DIR = "data"
DB_FILE = os.path.join(DB_DIR, "traffic.db")

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

def create_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        return conn
    except Error as e:
        print(f"Error connecting to database: {e}")
    return conn

def create_table(conn):
    sql_create_packets_table = """
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        size INTEGER NOT NULL
    );"""
    try:
        cursor = conn.cursor()
        cursor.execute(sql_create_packets_table)
    except Error as e:
        print(f"Error creating table: {e}")

def store_packet(conn, packet_data):
    sql = ''' INSERT INTO packets(timestamp, source_ip, destination_ip, protocol, size)
              VALUES(?,?,?,?,?) '''
    try:
        cursor = conn.cursor()
        cursor.execute(sql, packet_data)
        conn.commit()
    except Error as e:
        print(f"Error inserting packet: {e}")

def get_statistics(conn):
    stats = {}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM packets")
        stats['total_packets'] = cursor.fetchone()[0]
        cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
        stats['protocol_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
        cursor.execute("SELECT source_ip, COUNT(*) as count FROM packets GROUP BY source_ip ORDER BY count DESC LIMIT 5")
        stats['top_source_ips'] = cursor.fetchall()
        cursor.execute("SELECT destination_ip, COUNT(*) as count FROM packets GROUP BY destination_ip ORDER BY count DESC LIMIT 5")
        stats['top_destination_ips'] = cursor.fetchall()
        return stats
    except Error as e:
        print(f"Error fetching statistics: {e}")
        return None