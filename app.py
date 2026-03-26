import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify, g
)
from werkzeug.security import generate_password_hash, check_password_hash

# ── App Configuration ────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sy-traders-secret-key-2024")
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sy_traders.db")


# ── Database Helpers ─────────────────────────────────────────────────
def get_db():
    """Open a database connection and store it on the app‑context object."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed the default admin account."""
    db = sqlite3.connect(DATABASE)

    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        email       TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        role        TEXT DEFAULT 'user',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")

    db.execute("""CREATE TABLE IF NOT EXISTS products (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL,
        name        TEXT NOT NULL,
        brand       TEXT NOT NULL,
        category    TEXT NOT NULL,
        size        TEXT NOT NULL,
        color       TEXT NOT NULL,
        price       REAL NOT NULL,
        stock       INTEGER NOT NULL DEFAULT 0,
        description TEXT,
        date_added  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")

    db.execute("""CREATE TABLE IF NOT EXISTS sales (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        product_id    INTEGER NOT NULL,
        quantity      INTEGER NOT NULL,
        total_price   REAL NOT NULL,
        customer_name TEXT NOT NULL,
        sale_date     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id)    REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
    )""")

    # Seed admin
    admin = db.execute("SELECT id FROM users WHERE email = ?",
                       ("admin@example.com",)).fetchone()
    if not admin:
        db.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)",
            ("Admin", "admin@example.com",
             generate_password_hash("admin123"), "admin"),
        )
    db.commit()
    db.close()


init_db()  # runs once on startup


# ── Auth Decorators ──────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Auth Routes ──────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for(
            "admin_dashboard" if session.get("role") == "admin" else "dashboard"
        ))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("login.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?",
                          (email,)).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"]    = user["id"]
            session["user_name"]  = user["name"]
            session["user_email"] = user["email"]
            session["role"]       = user["role"]
            flash(f'Welcome back, {user["name"]}!', "success")
            return redirect(url_for(
                "admin_dashboard" if user["role"] == "admin" else "dashboard"
            ))
        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = request.form.get("name", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not all([name, email, password, confirm]):
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        db = get_db()
        if db.execute("SELECT id FROM users WHERE email = ?",
                      (email,)).fetchone():
            flash("Email already registered.", "danger")
            return render_template("register.html")

        db.execute(
            "INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
            (name, email, generate_password_hash(password), "user"),
        )
        db.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# ── User Dashboard ───────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    db  = get_db()
    uid = session["user_id"]

    products = db.execute(
        "SELECT * FROM products WHERE user_id=? ORDER BY date_added DESC",
        (uid,)).fetchall()

    sales = db.execute(
        """SELECT s.*, p.name AS product_name FROM sales s
           JOIN products p ON s.product_id=p.id
           WHERE s.user_id=? ORDER BY s.sale_date DESC""",
        (uid,)).fetchall()

    stats = {
        "total_products": len(products),
        "total_stock":    sum(p["stock"] for p in products),
        "total_sales":    len(sales),
        "total_revenue":  sum(s["total_price"] for s in sales),
    }
    return render_template("dashboard.html",
                           products=products, sales=sales, stats=stats)


# ── Product CRUD ─────────────────────────────────────────────────────
@app.route("/product/add", methods=["POST"])
@login_required
def add_product():
    name  = request.form.get("name", "").strip()
    brand = request.form.get("brand", "").strip()
    cat   = request.form.get("category", "").strip()
    size  = request.form.get("size", "").strip()
    color = request.form.get("color", "").strip()
    desc  = request.form.get("description", "").strip()

    try:
        price = float(request.form.get("price", 0))
        stock = int(request.form.get("stock", 0))
    except ValueError:
        flash("Invalid price or stock value.", "danger")
        return redirect(url_for("dashboard"))

    if not all([name, brand, cat, size, color]) or price <= 0:
        flash("Please fill in all required fields.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    db.execute(
        """INSERT INTO products
           (user_id,name,brand,category,size,color,price,stock,description)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (session["user_id"], name, brand, cat, size, color,
         price, stock, desc),
    )
    db.commit()
    flash("Product added successfully!", "success")
    return redirect(url_for("dashboard"))


@app.route("/product/edit/<int:pid>", methods=["POST"])
@login_required
def edit_product(pid):
    db = get_db()
    product = db.execute(
        "SELECT * FROM products WHERE id=? AND user_id=?",
        (pid, session["user_id"])).fetchone()

    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("dashboard"))

    try:
        price = float(request.form.get("price", 0))
        stock = int(request.form.get("stock", 0))
    except ValueError:
        flash("Invalid price or stock.", "danger")
        return redirect(url_for("dashboard"))

    db.execute(
        """UPDATE products SET name=?,brand=?,category=?,size=?,
           color=?,price=?,stock=?,description=?
           WHERE id=? AND user_id=?""",
        (
            request.form.get("name", "").strip(),
            request.form.get("brand", "").strip(),
            request.form.get("category", "").strip(),
            request.form.get("size", "").strip(),
            request.form.get("color", "").strip(),
            price, stock,
            request.form.get("description", "").strip(),
            pid, session["user_id"],
        ),
    )
    db.commit()
    flash("Product updated!", "success")
    return redirect(url_for("dashboard"))


@app.route("/product/delete/<int:pid>")
@login_required
def delete_product(pid):
    db = get_db()
    db.execute("DELETE FROM sales WHERE product_id=? AND user_id=?",
               (pid, session["user_id"]))
    db.execute("DELETE FROM products WHERE id=? AND user_id=?",
               (pid, session["user_id"]))
    db.commit()
    flash("Product deleted.", "success")
    return redirect(url_for("dashboard"))


# ── Sales ────────────────────────────────────────────────────────────
@app.route("/sale/add", methods=["POST"])
@login_required
def add_sale():
    customer = request.form.get("customer_name", "").strip()
    try:
        product_id = int(request.form.get("product_id", 0))
        quantity   = int(request.form.get("quantity", 0))
    except ValueError:
        flash("Invalid values.", "danger")
        return redirect(url_for("dashboard"))

    if not customer or quantity < 1:
        flash("Please fill in all fields.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    product = db.execute(
        "SELECT * FROM products WHERE id=? AND user_id=?",
        (product_id, session["user_id"])).fetchone()

    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for("dashboard"))
    if quantity > product["stock"]:
        flash("Insufficient stock.", "danger")
        return redirect(url_for("dashboard"))

    total = product["price"] * quantity
    db.execute(
        """INSERT INTO sales
           (user_id,product_id,quantity,total_price,customer_name)
           VALUES (?,?,?,?,?)""",
        (session["user_id"], product_id, quantity, total, customer),
    )
    db.execute("UPDATE products SET stock=stock-? WHERE id=?",
               (quantity, product_id))
    db.commit()
    flash("Sale recorded!", "success")
    return redirect(url_for("dashboard"))


# ── Admin Dashboard ──────────────────────────────────────────────────
@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()

    users = db.execute(
        "SELECT * FROM users ORDER BY created_at DESC").fetchall()
    products = db.execute(
        """SELECT p.*, u.name AS seller_name FROM products p
           JOIN users u ON p.user_id=u.id
           ORDER BY p.date_added DESC""").fetchall()
    sales = db.execute(
        """SELECT s.*, p.name AS product_name, u.name AS seller_name
           FROM sales s
           JOIN products p ON s.product_id=p.id
           JOIN users u ON s.user_id=u.id
           ORDER BY s.sale_date DESC""").fetchall()

    stats = {
        "total_users":    len([u for u in users if u["role"] != "admin"]),
        "total_products": len(products),
        "total_sales":    len(sales),
        "total_revenue":  sum(s["total_price"] for s in sales),
    }
    return render_template("admin.html",
                           users=users, products=products,
                           sales=sales, stats=stats)


@app.route("/admin/delete_user/<int:uid>")
@admin_required
def delete_user(uid):
    db   = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    if not user or user["role"] == "admin" or uid == session["user_id"]:
        flash("Cannot delete this user.", "danger")
        return redirect(url_for("admin_dashboard"))

    db.execute("DELETE FROM sales    WHERE user_id=?", (uid,))
    db.execute("DELETE FROM products WHERE user_id=?", (uid,))
    db.execute("DELETE FROM users    WHERE id=?",      (uid,))
    db.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ── Chart API Endpoints ──────────────────────────────────────────────
@app.route("/api/chart/categories")
@login_required
def chart_categories():
    db = get_db()
    if session.get("role") == "admin":
        rows = db.execute(
            "SELECT category, COUNT(*) AS cnt FROM products GROUP BY category"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT category, COUNT(*) AS cnt FROM products WHERE user_id=? GROUP BY category",
            (session["user_id"],)).fetchall()
    return jsonify(labels=[r["category"] for r in rows],
                   values=[r["cnt"]      for r in rows])


@app.route("/api/chart/sales")
@login_required
def chart_sales():
    db = get_db()
    if session.get("role") == "admin":
        rows = db.execute(
            """SELECT DATE(sale_date) AS d, SUM(total_price) AS rev
               FROM sales GROUP BY d ORDER BY d DESC LIMIT 7"""
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT DATE(sale_date) AS d, SUM(total_price) AS rev
               FROM sales WHERE user_id=? GROUP BY d ORDER BY d DESC LIMIT 7""",
            (session["user_id"],)).fetchall()
    rows = list(reversed(rows))
    return jsonify(labels=[r["d"]   for r in rows],
                   values=[r["rev"] for r in rows])


@app.route("/api/chart/top_products")
@login_required
def chart_top_products():
    db = get_db()
    if session.get("role") == "admin":
        rows = db.execute(
            """SELECT p.name, SUM(s.quantity) AS sold FROM sales s
               JOIN products p ON s.product_id=p.id
               GROUP BY p.name ORDER BY sold DESC LIMIT 5"""
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT p.name, SUM(s.quantity) AS sold FROM sales s
               JOIN products p ON s.product_id=p.id
               WHERE s.user_id=?
               GROUP BY p.name ORDER BY sold DESC LIMIT 5""",
            (session["user_id"],)).fetchall()
    return jsonify(labels=[r["name"] for r in rows],
                   values=[r["sold"] for r in rows])


# ── Run ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)