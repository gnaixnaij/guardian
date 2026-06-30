"""
Guardian Dashboard — Flask web UI for viewing alerts.
"""
import os
import json
import threading

from flask import Flask, render_template, jsonify

app = Flask(__name__)

guardian_instance = None


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def stats():
    if guardian_instance:
        return jsonify(guardian_instance.get_stats())
    return jsonify({"error": "Agent not running"})


@app.route("/api/alerts")
def alerts():
    if guardian_instance:
        return jsonify(guardian_instance.get_alerts(100))
    return jsonify([])


def run(guardian, host="127.0.0.1", port=5000):
    global guardian_instance
    guardian_instance = guardian
    app.run(host=host, port=port, debug=False)
