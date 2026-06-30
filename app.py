from flask import Flask, request, g, redirect, session, url_for, render_template
from flask import send_file
from reportlab.pdfgen import canvas
import socket
import sqlite3
import hashlib
import whois
import random
import string
import requests
import base64
import ssl
import urllib.parse
import ipaddress
import qrcode

from datetime import datetime
app = Flask(__name__)
app.secret_key = "mysecretkey123"

# -----------------------
# DATABASE SETUP
# -----------------------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("database.db")
    return g.db


def init_db():
    db = sqlite3.connect("database.db")
    db.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            endpoint TEXT,
            time TEXT
        )
    """)
    db.close()


# -----------------------
# AUTO LOGGING
# -----------------------

@app.before_request

def log_request():
    if request.path.startswith("/static") or request.path in ["/login", "/logout"]:
        return

    db = sqlite3.connect("database.db")

    db.execute(
        "INSERT INTO logs (ip, endpoint, time) VALUES (?, ?, ?)",
        (
            request.remote_addr,
            request.path,
            str(datetime.now())
        )
    )
    db.commit()
    db.close()


# -----------------------
# LOGIN
# -----------------------

USERNAME = "admin"
PASSWORD = "1234"


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        user = request.form["username"]
        pwd = request.form["password"]

        if user == USERNAME and pwd == PASSWORD:
            session["user"] = user
            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid Username or Password"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# -----------------------
# DASHBOARD
# -----------------------

@app.route("/")
def home():

    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        user=session["user"]
    )


# -----------------------
# LOGS
# -----------------------

@app.route("/logs")
def logs():

    if "user" not in session:
        return redirect(url_for("login"))

    db = sqlite3.connect("database.db")
    cursor = db.execute("SELECT * FROM logs ORDER BY id DESC")
    data = cursor.fetchall()
    db.close()

    return render_template("logs.html", logs=data)


# -----------------------
# PASSWORD CHECKER
# -----------------------

@app.route("/password-checker", methods=["GET", "POST"])
def password_checker():

    if "user" not in session:
        return redirect(url_for("login"))

    strength = ""

    if request.method == "POST":

        password = request.form["password"]

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if len(password) < 8:
            strength = "❌ Weak"
        elif has_upper and has_lower and has_digit and has_special:
            strength = "✅ Strong"
        else:
            strength = "⚠️ Medium"

    return render_template(
        "password_checker.html",
        strength=strength
    )


# -----------------------
# PORT SCANNER
# -----------------------

@app.route("/port-scanner", methods=["GET", "POST"])
def port_scanner():

    if "user" not in session:
        return redirect(url_for("login"))

    results = []

    if request.method == "POST":

        host = request.form["host"].strip()

        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443]

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            try:
                status = sock.connect_ex((host, port))
                if status == 0:
                    results.append((port, "OPEN"))
                else:
                    results.append((port, "CLOSED"))
            except Exception:
                results.append((port, "ERROR"))
            finally:
                sock.close()

    return render_template(
        "port_scanner.html",
        results=results
    )
# -----------------------
# HASH GENERATOR
# -----------------------

@app.route("/hash-generator", methods=["GET", "POST"])
def hash_generator():

    if "user" not in session:
        return redirect(url_for("login"))

    md5_hash = ""
    sha1_hash = ""
    sha256_hash = ""

    if request.method == "POST":

        text = request.form["text"]

        md5_hash = hashlib.md5(text.encode()).hexdigest()
        sha1_hash = hashlib.sha1(text.encode()).hexdigest()
        sha256_hash = hashlib.sha256(text.encode()).hexdigest()

    return render_template(
        "hash_generator.html",
        md5_hash=md5_hash,
        sha1_hash=sha1_hash,
        sha256_hash=sha256_hash
    )
# -----------------------
# DNS LOOKUP
# -----------------------

@app.route("/dns-lookup", methods=["GET", "POST"])
def dns_lookup():

    if "user" not in session:
        return redirect(url_for("login"))

    ip_address = ""

    if request.method == "POST":

        domain = request.form["domain"]

        try:
            ip_address = socket.gethostbyname(domain)
        except:
            ip_address = "Domain not found"

    return render_template(
        "dns_lookup.html",
        ip_address=ip_address
    )
# -----------------------
# WHOIS LOOKUP
# -----------------------

@app.route("/whois-lookup", methods=["GET", "POST"])
def whois_lookup():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        domain = request.form["domain"]

        try:
            info = whois.whois(domain)

            result = {
                "domain": info.domain_name,
                "registrar": info.registrar,
                "creation_date": info.creation_date,
                "expiration_date": info.expiration_date
            }

        except Exception:
            result = {
                "error": "Unable to fetch WHOIS information"
            }

    return render_template(
        "whois_lookup.html",
        result=result
    ) 
# -----------------------
# PDF REPORT GENERATOR
# -----------------------

@app.route("/generate-pdf")
def generate_pdf():

    if "user" not in session:
        return redirect(url_for("login"))

    pdf_file = "report.pdf"

    c = canvas.Canvas(pdf_file)

    c.setFont("Helvetica-Bold", 18)
    c.drawString(100, 800, "Ethical Hacking Toolkit Report")

    c.setFont("Helvetica", 12)
    c.drawString(100, 760, f"Generated By: {session['user']}")
    c.drawString(100, 740, "Status: Toolkit Running Successfully")

    c.drawString(100, 700, "Modules Installed:")

    c.drawString(120, 680, "- Password Checker")
    c.drawString(120, 660, "- Hash Generator")
    c.drawString(120, 640, "- DNS Lookup")
    c.drawString(120, 620, "- WHOIS Lookup")
    c.drawString(120, 600, "- Port Scanner")

    c.save()

    return send_file(
        pdf_file,
        as_attachment=True
    ) 
# -----------------------
# NETWORK SCANNER
# -----------------------

@app.route("/network-scanner", methods=["GET", "POST"])
def network_scanner():

    if "user" not in session:
        return redirect(url_for("login"))

    results = []

    if request.method == "POST":

        ip_base = request.form["ip_base"].strip()

        for i in range(1, 11):

            ip = f"{ip_base}.{i}"

            found = False

            for port in [80, 443]:

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)

                try:

                    status = sock.connect_ex((ip, port))

                    if status == 0:
                        results.append(
                            f"✅ Host Active: {ip} (Port {port} OPEN)"
                        )
                        found = True
                        break

                except Exception:
                    pass

                finally:
                    sock.close()

            if not found:
                results.append(
                    f"❌ Host Not Responding: {ip}"
                )

    return render_template(
        "network_scanner.html",
        results=results
    )
# -----------------------
# PASSWORD GENERATOR
# -----------------------

@app.route("/password-generator", methods=["GET", "POST"])
def password_generator():

    if "user" not in session:
        return redirect(url_for("login"))

    generated_password = ""

    if request.method == "POST":

        length = int(request.form["length"])

        characters = (
            string.ascii_letters +
            string.digits +
            string.punctuation
        )

        generated_password = "".join(
            random.choice(characters)
            for _ in range(length)
        )

    return render_template(
        "password_generator.html",
        generated_password=generated_password
    )
# -----------------------
# BASE64 ENCODER / DECODER
# -----------------------

@app.route("/base64-tool", methods=["GET", "POST"])
def base64_tool():

    if "user" not in session:
        return redirect(url_for("login"))

    encoded_text = ""
    decoded_text = ""

    if request.method == "POST":

        text = request.form["text"]
        action = request.form["action"]

        try:

            if action == "encode":

                encoded_text = base64.b64encode(
                    text.encode()
                ).decode()

            elif action == "decode":

                decoded_text = base64.b64decode(
                    text.encode()
                ).decode()

        except Exception:

            decoded_text = "Invalid Base64 Input"

    return render_template(
        "base64_tool.html",
        encoded_text=encoded_text,
        decoded_text=decoded_text
    )
# -----------------------
# IP GEOLOCATION LOOKUP
# -----------------------

@app.route("/ip-lookup", methods=["GET", "POST"])
def ip_lookup():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        ip = request.form["ip"]

        try:

            response = requests.get(
                f"http://ip-api.com/json/{ip}"
            )

            data = response.json()

            if data["status"] == "success":

                result = {
                    "ip": data["query"],
                    "country": data["country"],
                    "region": data["regionName"],
                    "city": data["city"],
                    "isp": data["isp"]
                }

            else:

                result = {
                    "error": "Invalid IP Address"
                }

        except Exception:

            result = {
                "error": "Unable to fetch IP information"
            }

    return render_template(
        "ip_lookup.html",
        result=result
    )

# -----------------------
# HTTP HEADER ANALYZER
# -----------------------

@app.route("/header-analyzer", methods=["GET", "POST"])
def header_analyzer():

    if "user" not in session:
        return redirect(url_for("login"))

    headers = None
    error = None

    if request.method == "POST":

        url = request.form["url"].strip()

        if not url.startswith("http"):
            url = "https://" + url

        try:

            response = requests.get(
                url,
                timeout=5
            )

            headers = dict(response.headers)

        except Exception:

            error = "Unable to fetch website headers"

    return render_template(
        "header_analyzer.html",
        headers=headers,
        error=error
    )
# -----------------------
# SSL CERTIFICATE CHECKER
# -----------------------

@app.route("/ssl-checker", methods=["GET", "POST"])
def ssl_checker():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        domain = request.form["domain"].strip()

        try:

            context = ssl.create_default_context()

            with context.wrap_socket(
                socket.socket(),
                server_hostname=domain
            ) as s:

                s.settimeout(5)
                s.connect((domain, 443))

                cert = s.getpeercert()

                result = {
                    "subject": dict(x[0] for x in cert["subject"]).get("commonName"),
                    "issuer": dict(x[0] for x in cert["issuer"]).get("commonName"),
                    "valid_from": cert["notBefore"],
                    "valid_until": cert["notAfter"]
                }

        except Exception:

            result = {
                "error": "Unable to fetch SSL certificate"
            }

    return render_template(
        "ssl_checker.html",
        result=result
    )
# -----------------------
# URL ENCODER / DECODER
# -----------------------

@app.route("/url-tool", methods=["GET", "POST"])
def url_tool():

    if "user" not in session:
        return redirect(url_for("login"))

    encoded_url = ""
    decoded_url = ""

    if request.method == "POST":

        text = request.form["text"]
        action = request.form["action"]

        try:

            if action == "encode":

                encoded_url = urllib.parse.quote(text)

            elif action == "decode":

                decoded_url = urllib.parse.unquote(text)

        except Exception:

            decoded_url = "Invalid Input"

    return render_template(
        "url_tool.html",
        encoded_url=encoded_url,
        decoded_url=decoded_url
    )
# -----------------------
# SUBNET CALCULATOR
# -----------------------

@app.route("/subnet-calculator", methods=["GET", "POST"])
def subnet_calculator():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        ip = request.form["ip"]
        cidr = request.form["cidr"]

        try:

            network = ipaddress.IPv4Network(
                f"{ip}/{cidr}",
                strict=False
            )

            result = {
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "subnet_mask": str(network.netmask),
                "total_hosts": network.num_addresses,
                "usable_hosts": max(network.num_addresses - 2, 0)
            }

        except Exception:

            result = {
                "error": "Invalid IP Address or CIDR"
            }

    return render_template(
        "subnet_calculator.html",
        result=result
    )
# -----------------------
# ROBOTS.TXT CHECKER
# -----------------------

@app.route("/robots-checker", methods=["GET", "POST"])
def robots_checker():

    if "user" not in session:
        return redirect(url_for("login"))

    robots_content = ""
    error = ""

    if request.method == "POST":

        domain = request.form["domain"].strip()

        if not domain.startswith("http"):
            url = f"https://{domain}/robots.txt"
        else:
            url = f"{domain}/robots.txt"

        try:

            response = requests.get(
                url,
                timeout=5
            )

            if response.status_code == 200:
                robots_content = response.text
            else:
                error = "robots.txt not found"

        except Exception:

            error = "Unable to fetch robots.txt"

    return render_template(
        "robots_checker.html",
        robots_content=robots_content,
        error=error
    )
# -----------------------
# SITEMAP FINDER
# -----------------------

@app.route("/sitemap-finder", methods=["GET", "POST"])
def sitemap_finder():

    if "user" not in session:
        return redirect(url_for("login"))

    sitemap_content = ""
    error = ""

    if request.method == "POST":

        domain = request.form["domain"].strip()

        if not domain.startswith("http"):
            url = f"https://{domain}/sitemap.xml"
        else:
            url = f"{domain}/sitemap.xml"

        try:

            response = requests.get(
                url,
                timeout=5
            )

            if response.status_code == 200:
                sitemap_content = response.text[:10000]
            else:
                error = "sitemap.xml not found"

        except Exception:

            error = "Unable to fetch sitemap.xml"

    return render_template(
        "sitemap_finder.html",
        sitemap_content=sitemap_content,
        error=error
    )
# -----------------------
# WEBSITE TECHNOLOGY DETECTOR
# -----------------------

@app.route("/technology-detector", methods=["GET", "POST"])
def technology_detector():

    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        url = request.form["url"].strip()

        if not url.startswith("http"):
            url = "https://" + url

        try:

            response = requests.get(
                url,
                timeout=5
            )

            headers = response.headers

            technologies = []

            server = headers.get("Server", "Unknown")
            powered = headers.get("X-Powered-By", "Unknown")

            technologies.append(f"Server: {server}")
            technologies.append(f"Powered By: {powered}")

            html = response.text.lower()

            if "wp-content" in html:
                technologies.append("WordPress Detected")

            if "react" in html:
                technologies.append("React Detected")

            if "_next" in html:
                technologies.append("Next.js Detected")

            if "bootstrap" in html:
                technologies.append("Bootstrap Detected")

            if "jquery" in html:
                technologies.append("jQuery Detected")

            result = technologies

        except Exception:

            result = [
                "Unable to detect technologies"
            ]

    return render_template(
        "technology_detector.html",
        result=result
    )

# -----------------------
# EMAIL HEADER ANALYZER
# -----------------------

@app.route("/email-header-analyzer", methods=["GET", "POST"])
def email_header_analyzer():

    if "user" not in session:
        return redirect(url_for("login"))

    result = {}

    if request.method == "POST":

        header = request.form["header"]

        lines = header.split("\n")

        for line in lines:

            if line.startswith("From:"):
                result["From"] = line.replace("From:", "").strip()

            elif line.startswith("To:"):
                result["To"] = line.replace("To:", "").strip()

            elif line.startswith("Subject:"):
                result["Subject"] = line.replace("Subject:", "").strip()

            elif line.startswith("Date:"):
                result["Date"] = line.replace("Date:", "").strip()

            elif line.startswith("Return-Path:"):
                result["Return-Path"] = line.replace("Return-Path:", "").strip()

    return render_template(
        "email_header_analyzer.html",
        result=result
    )
# -----------------------
# QR GENERATOR
# -----------------------

@app.route("/qr-generator", methods=["GET", "POST"])
def qr_generator():

    if "user" not in session:
        return redirect(url_for("login"))

    qr_image = None

    if request.method == "POST":

        data = request.form["data"]

        img = qrcode.make(data)

        img_path = "static/qr_code.png"

        img.save(img_path)

        qr_image = "qr_code.png"

    return render_template(
        "qr_generator.html",
        qr_image=qr_image
    )

# -----------------------
# MAIN
# -----------------------

import os

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
