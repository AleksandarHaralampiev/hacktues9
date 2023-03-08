from flask import Flask, render_template, request, make_response, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib

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

@app.route('/')
def home():
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
    

@app.route('/logout')
def left():
    session.pop("email", None)
    session.pop("remember", None)
    session.pop("password", None)
    return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)

