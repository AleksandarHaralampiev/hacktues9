from flask import Flask, render_template, request, make_response, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
from email.message import EmailMessage
import ssl
import smtplib
import random

#2fa configuration

email_sender = 'dataexotica@gmail.com'
email_password = 'atyocjltnmhlprgx'

import random
import string

import os
from email.message import EmailMessage
import ssl
import smtplib
import random


email_sender = 'dataexotica@gmail.com'
email_password = 'atyocjltnmhlprgx'


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '63103453574bccae5541fa05'
db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer(), primary_key = True)
    email = db.Column(db.String(), unique = True, nullable = False)
    username = db.Column(db.String(), unique = True, nullable = False)
    password = db.Column(db.String(), nullable = False)
    
class Combo(db.Model):
    __tablename__ = 'combo'
    id = db.Column(db.Integer(), primary_key = True)
    combo_username = db.Column(db.String(), nullable = False, unique = True)
    combo_password = db.Column(db.String(), nullable = False, unique = True)
    combo_website = db.Column(db.String(), nullable = False, unique = True)

# Routes
@app.route('/')
@app.route('/home')
def home():
    email = session.get('email')
    if email:
        return redirect(url_for('profile'))
    return render_template('home.html')



@app.route('/register', methods = ["POST", "GET"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        psw = request.form.get("password")
        psw_confirm = request.form.get("confirm_password")
        if User.query.filter_by(username=username).first():
            return render_template('register.html', message="Username already exists.")
        if User.query.filter_by(email=email).first():
            return render_template('register.html', message="Another account is using this email.")
        if psw != psw_confirm:
            return render_template('register.html', message="The passwords does not match.")
        
        hash_object = hashlib.sha256(psw.encode('utf-8'))
        hex_dig = hash_object.hexdigest()
        user = User(email=email, username=username, password = hex_dig)
        db.session.add(user)
        db.session.commit()
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    email = session.get('email')
    if email:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        email = request.form['email']
        email_receiver = email
        code = random.randint(100000, 999999)
        session['code'] = code  # store code in session

        subject = 'Verification Code'
        body = f'Your verification code is \n{code}'

        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
            server.login(email_sender, email_password)
            server.sendmail(email_sender, email_receiver, em.as_string())
        password = request.form['password']
        remember = request.form.get('remember', False)
        session['remember'] = remember
        user = User.query.filter_by(email=email).first()
        if user is None:
            return render_template('login.html', message="Invalid Credentials")
        hash_password = hashlib.sha256(password.encode()).hexdigest()
        if hash_password == user.password:
            session['email'] = email
            session['password'] = password
            if remember:
                session.permanent = True
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', message="Invalid Credentials")
    else:
        return render_template('login.html')
    





@app.route('/manager', methods=['GET', 'POST'])
def password_manager():
    if request.method == 'POST':
        combo_username = request.form['username']
        combo_password= request.form['password']
        combo_website = request.form['website']
        combo = Combo(combo_username=combo_username,combo_password=combo_password, combo_website=combo_website)
        db.session.add(combo)
        db.session.commit()
    return render_template('password_manager.html')




@app.route('/password_generator', methods=['POST', 'GET'])
def password_generator():
    if request.method == 'POST':
        chars = ""
        length = request.form.get('length', default = 12)
        length = int(length)
        uppercase = request.form.get('uppercase', False)
        lowercase = request.form.get('lowercase', False)
        numbers = request.form.get('numbers', False)
        symbols = request.form.get('symbols', False)
        if uppercase != False:
            chars += string.ascii_uppercase
        if lowercase != False:
            chars += string.ascii_lowercase
        if numbers != False:
            chars += string.digits
        if symbols != False:
            chars += string.punctuation 
        if chars == "":
            message = "Something went wrong"
            return render_template('password_generator.html', message=message)
        password = ''.join(random.choices(chars, k=length))
        return render_template('password_generator.html', password=password)


    return render_template('password_generator.html')
@app.route('/passowrd_cheecker', methods=["POST", "GET"])
def password_checker():
    if request.method == 'POST':
        
        password = request.form.get('password', '')
        upperCase = [1 if c in string.ascii_uppercase else 0 for c in password]
        lowerCase = [1 if c in string.ascii_lowercase else 0 for c in password]
        special = [1 if c in string.punctuation else 0 for c in password]
        numbers = [1 if c in string.digits else 0 for c in password]
        characters = [upperCase, lowerCase, special, numbers]
        length = len(password)
        
        score = 0
        
        # Check if password is in common list
        
        with open("commonPasswords.txt", "r") as f:
            commonPasswords = f.read().splitlines()
        
   
        # Add score for the length of the password
        
        if length > 8:
            score += 1
        
        if length > 12:
            score += 1
        
        if length > 16:
            score += 1
        
        if length > 20:
            score += 2
        
        # Add score for the number of different characters
        
        if sum(characters[0]) > 1:
            score += 1
        
        if sum(characters[1]) > 2:
            score += 1
        
        if sum(characters[2]) > 1:
            score += 2
        
        if sum(characters[3]) > 1:
            score += 1
        

        message = "Please enter a password"
        if password in commonPasswords:
            score = 0
        
        if score < 4:
            message = "The password is quite weak" + str(score) + "/10"
            return render_template('password_checker.html', message=message)
        elif score == 4:
             message = "The password is ok" + str(score) + "/10"
             return render_template('password_checker.html', message=message)
        elif score == 5:
            message = "The password is good" + str(score) + "/10"
            return render_template('password_checker.html', message=message)
        elif score < 8:
            message = "The password is very good" + str(score) + "/10"
            return render_template('password_checker.html', message=message)
        elif score <= 10:
            message = "The password is very strong" + str(score) + "/10"
            return render_template('password_checker.html', message=message)
    return render_template('password_checker.html')

@app.route('/profile')
def profile():
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    else:
        user = User.query.filter_by(email=email).first()
        return render_template('profile.html', email=email)
    
@app.route('/lectures')
def lectures():
    return render_template('lectures.html')



@app.route('/lectures_1')
def lecture_1():
    return render_template('lecture_1.html')

@app.route('/phishing')
def phishing():
    return render_template('phishing.html')
@app.route('/logout')
def left():
    session.pop("email", None)
    session.pop("remember", None)
    session.pop("password", None)
    return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)

