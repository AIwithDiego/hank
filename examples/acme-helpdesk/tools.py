"""Tools the support assistant can call."""
import smtplib
import sqlite3
import subprocess

DB = "shop.db"

TOOLS = [
    {
        "name": "query_orders",
        "description": "Run a SQL query against the shop database to look up orders.",
        "input_schema": {"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]},
    },
    {
        "name": "issue_refund",
        "description": "Refund an order.",
        "input_schema": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}, "amount_eur": {"type": "number"}},
            "required": ["order_id", "amount_eur"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email on behalf of Acme Outdoor.",
        "input_schema": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "track_parcel",
        "description": "Get the delivery status for a tracking number.",
        "input_schema": {"type": "object", "properties": {"tracking": {"type": "string"}}, "required": ["tracking"]},
    },
]


def run_tool(name, args):
    if name == "query_orders":
        with sqlite3.connect(DB) as conn:
            return str(conn.execute(args["sql"]).fetchall())
    if name == "issue_refund":
        with sqlite3.connect(DB) as conn:
            conn.execute(
                "INSERT INTO refunds (order_id, amount_eur) VALUES (?, ?)",
                (args["order_id"], args["amount_eur"]),
            )
        return "refunded"
    if name == "send_email":
        with smtplib.SMTP("localhost") as smtp:
            smtp.sendmail("help@acme.example", args["to"], f"Subject: {args['subject']}\n\n{args['body']}")
        return "sent"
    if name == "track_parcel":
        out = subprocess.run(f"./carrier-cli status {args['tracking']}", shell=True, capture_output=True, text=True)
        return out.stdout
    return "unknown tool"
