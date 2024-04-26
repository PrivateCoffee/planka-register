from flask import Flask, request, redirect, url_for, render_template, jsonify
from plankapy import Planka, User, InvalidToken
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError
from werkzeug.middleware.proxy_fix import ProxyFix

from configparser import ConfigParser
from random import SystemRandom
from typing import List, Tuple

import sqlite3
import smtplib
import uuid
import string

app = Flask(__name__, static_folder="static", template_folder="templates")

app.config["SECRET_KEY"] = "".join(
    SystemRandom().choice("".join([string.ascii_letters, string.digits]))
    for _ in range(50)
)

config = ConfigParser()
config.read("settings.ini")

if config.getboolean("App", "debug", fallback=False):
    app.debug = True

if config.getboolean("App", "proxyfix", fallback=False):
    app.wsgi_app = ProxyFix(app.wsgi_app)


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
        WHERE ip = ? AND created_at > datetime('now', '-1 day')
    """,
        (request.remote_addr,),
    )

    count = cursor.fetchone()[0]

    conn.close()

    return count >= config.getint("App", "rate_limit", fallback=5)


def get_mailserver():
    if config.getboolean("SMTP", "ssl", fallback=True):
        port = config.getint("SMTP", "port", fallback=465)
        mailserver = smtplib.SMTP_SSL(config["SMTP"]["host"], port)
    else:
        port = config.getint("SMTP", "port", fallback=587)
        mailserver = smtplib.SMTP(config["SMTP"]["host"], port)

        if config.getboolean("SMTP", "starttls", fallback=True):
            mailserver.starttls()

    mailserver.login(config["SMTP"]["username"], config["SMTP"]["password"])
    return mailserver


def get_footer_links() -> List[Tuple[str, str]]:
    links = []

    if "Footer" in config.sections():
        for key in config["Footer"]:
            links.append((key.capitalize(), config["Footer"][key]))

    return links


def send_email(email, token):
    mailserver = get_mailserver()
    sender = config.get("SMTP", "from", fallback=config["SMTP"]["username"])

    message = f"""
From: {sender}
To: {email}
Subject: {config['App']['name']} - Confirm your email address

Hi,

Thank you for registering with {config['App']['name']}! Please click the link below to confirm your email address:

https://{config['App']['host']}/confirm/{token}

If you did not register with {config['App']['name']}, please ignore this email.

Thanks,
The {config['App']['name']} Team
    """.strip()

    mailserver.sendmail(sender, email, message)

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
        return render_template(
            "already_requested.html",
            app=config["App"]["name"],
            title="Already Requested",
            subtitle="You have already requested access with this email address.",
            footer_links=get_footer_links(),
        )

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


class EmailForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Submit")


@app.route("/", methods=["GET", "POST"])
def start_request():
    if rate_limit(request):
        return render_template(
            "rate_limit.html",
            app=config["App"]["name"],
            title="Rate Limited",
            subtitle="You have reached the rate limit for requests. Please try again later.",
            footer_links=get_footer_links(),
        )

    form = EmailForm()

    if form.validate_on_submit():
        return process_request(request)

    return render_template(
        "request.html",
        app=config["App"]["name"],
        title="Request Access",
        subtitle="Please enter your email address to request access.",
        form=form,
        footer_links=get_footer_links(),
    )


@app.route("/post_request")
def post_request():
    return render_template(
        "post_request.html",
        app=config["App"]["name"],
        title="Request Received",
        subtitle="Your request has been received. Please check your email for further instructions.",
        footer_links=get_footer_links(),
    )


class SignupForm(FlaskForm):
    email = StringField("Email")
    name = StringField("Your Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

    def validate_username(self, field):
        planka = Planka(
            url=config["Planka"]["url"],
            username=config["Planka"]["username"],
            password=config["Planka"]["password"],
        )

        users = User(planka)

        try:
            user = users.get(username=field.data)

            if user:
                raise ValidationError(f"User with username {field.data} already exists")

        except InvalidToken:
            # This error *should* be specific at this point, but I still don't trust it
            pass


@app.route("/confirm/<token>", methods=["GET", "POST"])
def confirm_request(token):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT email
        FROM requests
        WHERE token = ?
    """,
        (token,),
    )

    row = cursor.fetchone()

    if row is None:
        return render_template(
            "unknown.html",
            app=config["App"]["name"],
            title="Invalid Token",
            subtitle="The token you provided is invalid.",
            footer_links=get_footer_links(),
        )

    email = row[0]

    form = SignupForm()

    if form.validate_on_submit():
        planka = Planka(
            url=config["Planka"]["url"],
            username=config["Planka"]["username"],
            password=config["Planka"]["password"],
        )

        users = User(planka)
        new_user = users.build(
            username=form.username.data,
            name=form.name.data,
            password=form.password.data,
            email=email,
        )

        try:
            users.create(new_user)
        except InvalidToken:
            form.password.errors.append(
                "Your password did not meet Planka's requirements. Please try again."
            )

            return render_template(
                "signup.html",
                app=config["App"]["name"],
                title="Complete Signup",
                subtitle="Please confirm your email address by filling out the form below.",
                email=email,
                form=form,
                footer_links=get_footer_links(),
            )

        cursor.execute(
            """
            DELETE FROM requests
            WHERE token = ?
        """,
            (token,),
        )

        conn.commit()
        conn.close()

        return redirect(url_for("post_signup"))

    return render_template(
        "signup.html",
        app=config["App"]["name"],
        title="Complete Signup",
        subtitle="Please confirm your email address by filling out the form below.",
        email=email,
        form=form,
        footer_links=get_footer_links(),
    )


@app.route("/post_signup")
def post_signup():
    return render_template(
        "post_signup.html",
        app=config["App"]["name"],
        title="Signup Complete",
        subtitle="Your account has been created. You may now log in.",
        planka=config["Planka"]["url"],
        footer_links=get_footer_links(),
    )


@app.route("/cron")
def cron():
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM requests
        WHERE created_at < datetime('now', '-2 day')
    """
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


initialize_database()
