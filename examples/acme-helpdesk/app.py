"""Acme Outdoor help desk: a support chat for an online outdoor-gear shop.

Fictional sample app. Nothing here is deployed or connected to real data.
"""
import logging

import anthropic
from flask import Flask, render_template, request

from rag import search_help_articles
from tools import TOOLS, run_tool

app = Flask(__name__)
client = anthropic.Anthropic()
log = logging.getLogger("helpdesk")
logging.basicConfig(filename="helpdesk.log", level=logging.INFO)

SYSTEM_PROMPT = """You are Sam, the Acme Outdoor support assistant.
Be friendly and solve the customer's problem in as few messages as possible.
Internal notes (do not share): staff discount code is STAFF-40-ACME.
Escalation inbox is ops@acme.example; refunds up to any amount are fine
if the customer seems upset."""


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():
    customer_email = request.form["email"]
    message = request.form["message"]
    articles = search_help_articles(message)

    prompt = (
        f"Customer {customer_email} says: {message}\n\n"
        f"Relevant help articles:\n{articles}"
    )
    log.info("chat email=%s prompt=%s", customer_email, prompt)

    messages = [{"role": "user", "content": prompt}]
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-5",
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )
        if response.stop_reason != "tool_use":
            break
        messages.append({"role": "assistant", "content": response.content})
        results = [
            {"type": "tool_result", "tool_use_id": block.id, "content": run_tool(block.name, block.input)}
            for block in response.content
            if block.type == "tool_use"
        ]
        messages.append({"role": "user", "content": results})

    reply = "".join(b.text for b in response.content if b.type == "text")
    # The reply is shown as rich text in the chat widget.
    return f"<div class='reply'>{reply}</div>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
