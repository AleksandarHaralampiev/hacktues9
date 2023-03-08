from website import app
from flask import render_template, redirect, url_for

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')