from flask import Flask, render_template, request, make_response, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
from email.message import EmailMessage
import ssl
import smtplib
import random
import requests
from bs4 import BeautifulSoup
import json
from newsapi import NewsApiClient

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
        return redirect(url_for('verification'))
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
            return redirect(url_for('verification'))
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
        length = request.form.get('length')
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
    email = session.get('email')
    remember = session.get('remember')
    if email is None:
            if remember != True:
                return redirect(url_for('login'))
    if request.method == 'POST':
            score = 0
            password = request.form.get('password', '')
            if password == None:
                return render_template('password_checker.html')
            if len(password) < 12:
                score += 1
            elif len(password) >= 12:
                score += 3
        # Check for presence of numbers, uppercase and lowercase letters
            has_digit = False
            has_uppercase = False
            has_lowercase = False
            for char in password:
                if char.isdigit():
                    has_digit = True
                elif char.isupper():
                    has_uppercase = True
                elif char.islower():
                    has_lowercase = True
    
            # Check if all character types are present
            if has_digit and has_uppercase and has_lowercase:
                score += 3
            elif (has_digit and has_uppercase) or (has_digit and has_lowercase) or (has_uppercase and has_lowercase):
                score += 2
            elif has_digit or has_uppercase or has_lowercase:
                score += 1
    
            # Add bonus points for special characters
            special_characters = "!@#$%^&*()-_=+[]{};:'\"<>,.?\\|/"
            has_special = False
            for char in password:
                if char in special_characters:
                    has_special = True
                    break
            if has_special:
                score += 4
            
            if (score <= 3):
                message = "The password is weak"
                emoji = "😭"
            elif(score <= 7):
                message = "The password is good"
                emoji = "😐"
            elif (score <= 9):
                message = "The password is strong"
                emoji = "😀"
            elif(score == 10):
                message = "The password is really strong"
                emoji = "💪"
            # Map score to a 1-10 scale
            width = score * 10
            width = str(width) + "%"
            return render_template('password_checker.html', score=score, message=message, width=width,emoji=emoji)
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

@app.route('/verification', methods=['GET', 'POST'])
def verification():
    print("hello world")
    if request.method == 'POST':
        code= int(request.form['code'])
        if code == (session['code']):
            return redirect(url_for('profile'))
        else:   
            flash('Invalid Code')
            return render_template('auth.html')
    else:
        return render_template('auth.html')
    
@app.route('/lectures')
def lectures():
    return render_template('lectures.html')

@app.route('/phishing_1', methods=['GET', 'POST'])
def phishing_1():
    if request.method == 'POST':
        login_email = request.form['login_email']
        login_password = request.form['login_password']
        session['login_email'] = login_email
        session['login_password'] = login_password
        
        
        
    return render_template('visualization.html')



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

@app.route('/visualization')
def visualization():
    return render_template('visualization.html')

@app.route('/linkcheckup', methods=['GET', 'POST'])
def check_link():
    if request.method == 'POST':
        url = request.form.get('url')
        headers = {'x-api-key' : 'af40ee35-089b-426a-a6db-f00bf4fc1ffb'}

        mxtoolbox_url = f'https://api.geekflare.com/dnsrecord'
        payloat = {
            'url':url
        }
        response = requests.post(mxtoolbox_url, json=payloat, headers=headers)
        
        # soup = BeautifulSoup(response.text, 'html.parser')
        # result_div = soup.find('', {'': ''})
        
        
        output = response.json()
        
        # result_div = output
        apiCode = output['apiCode']
        if apiCode == 404:
            # return
            print("error 404")
            
        result_ip = output['data']['A'][0]['address']
        result_ttl = output['data']['A'][0]['ttl']
        result_txt = output['data']['TXT']
        result_txt_output = []
        for txt in output['data']['TXT']:
            result_txt_output.append(txt)
        
        if result_ip is not None:
            result_text = result_ip
        else:
            result_text = 'No results found.'
            
        if result_ttl is not None:
            result_text_one = result_ttl
        else:
            result_text_one = 'No results found.'

        result_div= None
        return render_template('link_checkup.html', url=url, result=result_text, result_one = result_text_one, txt_result = result_txt_output )

    return render_template('link_checkup.html')

@app.route('/news')
def Index():
    newsapi = NewsApiClient(api_key='edec7dc4223146d2bcac02d1555fc925')
    topheadlines = newsapi.get_everything(q='cybersecurity',
                                          language='en',
                                          sort_by = 'publishedAt',
                                          page_size=5
                                          )
                                        
    articles = topheadlines['articles']

    desc = []
    news = []
    link = []
    img = []


    for i in range(len(articles)):
        myarticles = articles[i]


        news.append(myarticles['title'])
        desc.append(myarticles['content'])
        img.append(myarticles['urlToImage'])
        link.append(myarticles['url'])



    mylist = zip(news, desc, link, img)


    return render_template('news.html', context = mylist)

if __name__ == "__main__":
    app.run(debug=True)

