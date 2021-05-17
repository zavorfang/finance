import os

from cs50 import SQL
from flask import Flask, url_for, flash, redirect, render_template, request, session
from flask_session import Session
import datetime
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.globals.update(round=round)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    # DECLARING ALL VALUES IN PAYLOAD
    rows = db.execute("SELECT * FROM users WHERE id=?", user_id)
    balance = rows[0]['cash']
    rows = db.execute("SELECT DISTINCT symbol FROM trades WHERE user_id=? AND trade='bought' ORDER BY id ASC", user_id)

    the_bag = 0.0

    symbols = []
    for row in rows:
        symbols.append(row['symbol'])

    stocks = []


    # GETTING ALL TRANSACTION BASED ON ONE STOCK
    # AND ACQUIRING THE AGGREGATE OF BOUGHT AND SOLD
    # IN ORDER TO GET WHATS AVAILABLE IN THE PORTFOLIO

    for symbol in symbols:
        # ALL BOUGHT SHARES
        b = db.execute("SELECT SUM(quantity) FROM trades WHERE user_id=? AND symbol=? GROUP BY symbol", user_id, symbol)

        # CALCULATING AGGREGATE
        aggregor = b[0][list(b[0].keys())[0]]

        # GETTING CURRENT PRICE
        quote = lookup(symbol)
        price = quote['price']
        name = quote['name']

        stock = {'symbol': symbol, 'name': name, 'shares': aggregor, 'price': price}
        stocks.append(stock)

        # TOTAL VALUE OF INDIVIDUALLY POSSESSED STOCK
        total = price*aggregor
        # VALUE OF ALL STOCKS IN THE PORTFOLIO
        the_bag += total

    values = {'balance': balance, 'the_bag': the_bag, 'stocks': stocks}

    return render_template("index.html", values=values)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form['symbol']
        user_id = session["user_id"]
        quote = lookup(symbol)

        # Checking if stock is valid
        if quote is None:
            return apology("Invalid symbol", 400)

        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("shares must be a posative integer", 400)

        if shares < 1:
            return apology("Select at least one share", 400)

        if str(type(shares)) is not "<class 'int'>":
            return apology("Invalid symbol", 400)

        shares = float(shares)


        total = quote['price']*shares
        name = quote['name']
        date = datetime.datetime.now()
        bought_at = quote['price']

        rows = db.execute("SELECT * FROM users WHERE id=?", user_id)
        balance = rows[0]['cash']

        if total > balance:
            return apology("Can't afford", 400)

        db.execute("UPDATE users SET cash=? WHERE id=?", balance-total, user_id)

        db.execute("INSERT INTO trades(user_id, symbol, name, date, initial, trade, quantity) VALUES(?, ?, ?, ?, ?, ?, ?)", user_id, symbol, name, date, bought_at, "bought", shares)
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    sql = "select * from trades where user_id=? order by date ASC"
    rows = db.execute(sql, session['user_id'])

    return render_template("history.html", values=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form['symbol'])
        if quote is None:
            return apology("stock doesn't exist", 400)
        return render_template("quote.html", quote=quote)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        uname = request.form['username']
        password = request.form['password']
        conpassword = request.form['confirmation']
        rows = db.execute("SELECT * FROM users WHERE username = ?", uname)

        if not uname:
            return apology("Please enter a valid username", 400)

        if not password:
            return apology("Please enter a valid username", 400)

        if len(rows) >= 1:
            return apology("User already exists", 400)

        if password != conpassword:
            return apology("Password do not match", 400)

        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", uname, generate_password_hash(password))
        flash("Registration successfully!")

        rows = db.execute("SELECT * FROM users WHERE username = ?", uname)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    rows = db.execute("SELECT symbol, SUM(quantity) as total FROM trades WHERE user_id=? GROUP BY symbol", user_id)

    # CALCULATING AGGREGATE
    symbols = []
    for row in rows:
        if row['total'] > 0:
            symbols.append(row['symbol'])

    payload = {'symbols': symbols}

    if request.method == "POST":
        symbol = request.form['symbol']
        quote = lookup(symbol)

        # Checking if stock is valid
        if quote is None:
            return apology("Invalid symbol", 400)

        shares = int(request.form['shares'])

        if shares < 1:
            return apology("Select at least one share", 400)

        b = db.execute("SELECT SUM(quantity) FROM trades WHERE user_id=? AND symbol=? GROUP BY symbol", user_id, symbol)

        # CALCULATING AGGREGATE
        aggregor = b[0][list(b[0].keys())[0]]

        if shares > aggregor:
            return apology("You don't possess adequate shares", 400)

        total = quote['price']*float(shares)
        name = quote['name']
        date = datetime.datetime.now()
        sold_at = quote['price']

        rows = db.execute("SELECT * FROM users WHERE id=?", user_id)
        balance = rows[0]['cash']
        shares = -shares

        db.execute("UPDATE users SET cash=? WHERE id=?", balance+total, user_id)

        db.execute("INSERT INTO trades(user_id, symbol, name, date, initial, trade, quantity) VALUES(?, ?, ?, ?, ?, ?, ?)", user_id, symbol, name, date, sold_at, "sold", shares)
        return redirect("/")

    return render_template("sell.html", values=payload)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == '__main__':
    app.run(debug=True)