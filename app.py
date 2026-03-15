from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secretkey"

# Path to upload evidence files
UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# ---------------------- DATABASE INIT ----------------------
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    # Reports table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        type TEXT,
        severity TEXT,
        location TEXT,
        description TEXT,
        evidence TEXT,
        time TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()


# ---------------------- HOME ----------------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------------- REGISTER ----------------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users(name,email,password) VALUES(?,?,?)",
                (name,email,password)
            )
            conn.commit()
            flash("Registration successful!", "success")
            return redirect("/login")
        except:
            flash("Email already exists!", "error")
        conn.close()

    return render_template("register.html")


# ---------------------- LOGIN ----------------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=?",(email,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user"] = user[1]
            session["user_email"] = user[2]
            flash("Login successful!", "success")
            return redirect("/dashboard")
        else:
            flash("Invalid email or password", "error")

    return render_template("login.html")


# ---------------------- DASHBOARD ----------------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # Total reports
    cur.execute("SELECT COUNT(*) FROM reports")
    total_reports = cur.fetchone()[0]

    # SOS alerts (dummy value for now)
    total_sos = 5

    # Filters
    type_filter = request.args.get("type_filter", "")
    severity_filter = request.args.get("severity_filter", "")

    query = "SELECT * FROM reports WHERE 1=1"
    params = []
    if type_filter:
        query += " AND type=?"
        params.append(type_filter)
    if severity_filter:
        query += " AND severity=?"
        params.append(severity_filter)

    cur.execute(query, params)
    reports = cur.fetchall()

    # Chart data
    cur.execute("SELECT type, COUNT(*) FROM reports GROUP BY type")
    chart = cur.fetchall()
    chart_labels = [row[0] for row in chart]
    chart_data = [row[1] for row in chart]

    conn.close()

    return render_template("dashboard.html",
                           name=session["user"],
                           total_reports=total_reports,
                           total_sos=total_sos,
                           reports=reports,
                           chart_labels=chart_labels,
                           chart_data=chart_data)


# ---------------------- DELETE REPORT ----------------------
@app.route("/delete_report/<int:report_id>", methods=["POST"])
def delete_report(report_id):
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM reports WHERE id=?", (report_id,))
    conn.commit()
    conn.close()
    flash("Report deleted successfully!", "success")
    return redirect("/dashboard")


# ---------------------- LOGOUT ----------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("user_email", None)
    flash("Logged out successfully", "success")
    return redirect("/")


# ---------------------- SOS PAGE ----------------------
@app.route("/sos")
def sos():
    if "user" not in session:
        return redirect("/login")
    return render_template("sos.html")


# ---------------------- REPORT INCIDENT ----------------------
@app.route("/report", methods=["GET","POST"])
def report():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        name = session["user"]
        email = session["user_email"]
        r_type = request.form.get("type")
        severity = request.form.get("severity")
        location = request.form.get("location")
        description = request.form.get("description")
        time_now = request.form.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M")

        # Handle evidence file
        evidence_file = request.files.get("evidence")
        evidence_path = ""
        if evidence_file:
            filename = datetime.now().strftime("%Y%m%d%H%M%S_") + evidence_file.filename
            evidence_file.save(os.path.join(UPLOAD_FOLDER, filename))
            evidence_path = os.path.join('uploads', filename)  # store relative to static/

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports(name,email,type,severity,location,description,evidence,time)
            VALUES(?,?,?,?,?,?,?,?)
        """, (name,email,r_type,severity,location,description,evidence_path,time_now))
        conn.commit()
        conn.close()

        flash("Report submitted successfully!", "success")
        return redirect("/dashboard")

    return render_template("report.html")


# ---------------------- VIEW REPORTS ----------------------
@app.route("/view_reports")
def view_reports():
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM reports")
    data = cur.fetchall()
    conn.close()
    return render_template("view_reports.html", reports=data)


# ---------------------- SAFETY TIPS ----------------------
@app.route("/tips")
def tips():
    return render_template("tips.html")


# ---------------------- RUN APP ----------------------
if __name__ == "__main__":
    app.run(debug=True)