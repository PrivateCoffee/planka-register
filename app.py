from flask import Flask, request, redirect, url_for, render_template
from plankapy import Planka

from configparser import ConfigParser

import sqlite3
import smtplib
import uuid

app = Flask(__name__, static_folder="static", template_folder="templates")

config = ConfigParser()
config.read("settings.ini")


def initialize_database():
    conn = sqlite3.connect("db.sqlite3")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            ip TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    conn.close()


def rate_limit(request):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM requests
        WHERE ip = ? AND created_at > datetime('now', '-1 hour')
    """,
        (request.remote_addr,),
    )

    count = cursor.fetchone()[0]

    conn.close()

    return count >= config.getint("App", "rate_limit", fallback=5)


def get_mailserver():
    if config["SMTP"]["ssl"] == "True":
        port = config.getint("SMTP", "port", fallback=465)
        mailserver = smtplib.SMTP_SSL(config["SMTP"]["host"], port)
    else:
        port = config.getint("SMTP", "port", fallback=587)
        mailserver = smtplib.SMTP(config["SMTP"]["host"], port)

        if config.getboolean("SMTP", "starttls", fallback=True):
            mailserver.starttls()

    mailserver.login(config["SMTP"]["username"], config["SMTP"]["password"])
    return mailserver


def send_email(email, token):
    mailserver = get_mailserver()

    message = f"""
        From: {config['SMTP']['from']}
        To: {email}
        Subject: Confirm your email address

        Hi,

        Thank you for registering with {config['App']['name']}! Please click the link below to confirm your email address:

        https://{config['App']['domain']}/confirm/{token}

        If you did not register with {config['App']['name']}, please ignore this email.

        Thanks,
        The {config['App']['name']} Team
    """

    mailserver.sendmail(config["SMTP"]["from"], email, message)

    mailserver.quit()


def process_request(request):
    email = request.form["email"]

    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()

    # Check if the email address is already in the database
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM requests
        WHERE email = ?
    """,
        (email,),
    )

    count = cursor.fetchone()[0]

    if count > 0:
        return render_template("already_requested.html")

    token = str(uuid.uuid4())

    cursor.execute(
        """
        INSERT INTO requests (email, token, ip)
        VALUES (?, ?, ?)
    """,
        (email, token, request.remote_addr),
    )

    conn.commit()
    conn.close()

    send_email(email, token)

    return redirect(url_for("post_request"))


@app.route("/", methods=["GET", "POST"])
def start_request():
    if rate_limit(request):
        return render_template("rate_limit.html")

    if request.method == "POST":
        return process_request(request)

    return render_template(
        "request.html",
        app=config["App"]["name"],
        title="Request Access",
        subtitle="Please enter your email address to request access.",
    )


@app.route("/check", methods=["GET"])
def check():
    return render_template("check.html")


initialize_database()
