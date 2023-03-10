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
import openai


openai.api_key = "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"

INSTRUCTIONS = """You are an AI assistant that is a cybersecurity expert.
You know all about the different cyber attacks and cyber protection.
You can advise how to prevent cyber attacks, what to do if the user is attacked and answer questions about cybersecurity.
If you are unable to provide an answer to a question or the question is not associated with cybersecurity, please respond with the phrase "I'm just a cybersecurity expert, I can't help with that."
Do not use any external URLs in your answers. Do not refer to any blogs in your answers.
Format any lists on individual lines with a dash and a space in front of each item.Never answer other questions except cybersecurity."""
TEMPERATURE = 0.5
MAX_TOKENS = 500
FREQUENCY_PENALTY = 0
PRESENCE_PENALTY = 0.6
MAX_CONTEXT_QUESTIONS = 10
previous_questions_and_answers = []


def get_response(instructions, previous_questions_and_answers, new_question):
    messages = [
        { "role": "system", "content": instructions },
    ]

    for question, answer in previous_questions_and_answers[-MAX_CONTEXT_QUESTIONS:]:
        messages.append({ "role": "user", "content": question })
        messages.append({ "role": "assistant", "content": answer })
    
    messages.append({ "role": "user", "content": new_question })

    completion = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
        top_p=1,
        frequency_penalty=FREQUENCY_PENALTY,
        presence_penalty=PRESENCE_PENALTY,
    )

    return completion.choices[0].message.content


def get_moderation(question):
    errors = {
        "hate": "Content that expresses, incites, or promotes hate based on race, gender, ethnicity, religion, nationality, sexual orientation, disability status, or caste.",
        "hate/threatening": "Hateful content that also includes violence or serious harm towards the targeted group.",
        "self-harm": "Content that promotes, encourages, or depicts acts of self-harm, such as suicide, cutting, and eating disorders.",
        "sexual": "Content meant to arouse sexual excitement, such as the description of sexual activity, or that promotes sexual services (excluding sex education and wellness).",
        "sexual/minors": "Sexual content that includes an individual who is under 18 years old.",
        "violence": "Content that promotes or glorifies violence or celebrates the suffering or humiliation of others.",
        "violence/graphic": "Violent content that depicts death, violence, or serious physical injury in extreme graphic detail.",
    }

    response = openai.Moderation.create(input=question)

    if response.results[0].flagged:
        result = [
            error
            for category, error in errors.items()
            if response.results[0].categories[category]
        ]
        return result
    
    return None

def get_answer(new_question):
    errors = get_moderation(new_question)
    if errors:
        return "Sorry, you're question didn't pass the moderation check"
    
    response = get_response(INSTRUCTIONS, previous_questions_and_answers, new_question)
    
    previous_questions_and_answers.append((new_question, response))
    
    return response
#



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

    return render_template('home.html', context = mylist)



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
        question = request.form.get('message')
        if question:
            answer = get_answer(question)
            if question and answer:
                return render_template('popup.html', question = question, answer=answer)
        else :
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
@app.route('/passowrd_checker', methods=["POST", "GET"])
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



@app.route('/profile', methods = ['POST', 'GET'])
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

@app.route('/test', methods = ['POST', 'GET'])
def test():
    if request.method == 'POST':
        question = request.form.get('message')
        if not question:
            return render_template('popup.html')
        answer = get_answer(question)
        if question and answer:
            return render_template('popup.html', question = question, answer=answer)
    else :return render_template('popup.html')
    return render_template('popup.html')

@app.route('/lectures_1')
def lecture_1():
    return render_template('lecture_1.html')

@app.route('/phishing')
def phishing():

    return render_template('phishing.html')


@app.route('/logout')
def left():
    session.pop('email', None)
    session.pop('remember', None)
    session.pop('password', None)
    return redirect('/')

@app.route('/visualization')
def visualization():
    email = session.get('email')
    remember = session.get('remember')
    password = session.get('password')
    
    return render_template('visualization.html', email=email, remember=remember, password=password)

@app.route('/visualization_1', methods = ['POST'])
def visualization_1():
    email = session.get('email')
    remember = session.get('remember')
    password = session.get('password')
    
    return render_template('visualization_1.html', email=email, remember=remember, password=password)
    

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

