import json
from flask import Flask, render_template, redirect, url_for, session, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
import pymysql
import bcrypt
import jsonify
from functools import wraps
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'

a = 'mysql+pymysql://root:@localhost/my_db'

app.config['SQLALCHEMY_DATABASE_URI'] = a


bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    rollno = db.Column(db.String(20))
    u_type = db.Column(db.String(8))
    class_name = db.Column(db.String(10))
    admission_no = db.Column(db.String(17))
    application_no = db.Column(db.String(25))
    department = db.Column(db.String(8))
    id_no = db.Column(db.String(15))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('', validators=[InputRequired(), Length(min=8, max=80)])
    roll_no = StringField('', validators=[InputRequired(), Length(min=4, max=25)])
    user_type = SelectField('', choices=[('student', 'student'), ('faculty', 'faculty'), ('admin', 'admin')])


def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'student-logged-in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap


def faculty_login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'faculty-logged-in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap


@app.route('/')
def index():
    return render_template('index.html')


log_username = ''


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if request.method == 'POST':
        # if form.validate_on_submit():
        user = User.query.filter_by(rollno=form.username.data).first()
        if user is None or user.rollno != form.username.data or user.password != form.password.data:
            flash('Invalid username or password')
        else:

            global log_username
            log_username = user.username, user.class_name, user.admission_no, user.application_no, user.department, user.rollno, user.id_no
            session['log_username'] = log_username
            if user.u_type == 'admin':
                session['admin-logged-in'] = True
                return 'admin login'
            elif user.u_type == 'faculty':
                session['faculty-logged-in'] = True
                return redirect(url_for('faculty_dashboard'))
            else:
                session['student-logged-in'] = True
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form, error=error)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data, rollno=form.roll_no.data, u_type=form.user_type.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=log_username[0])


@app.route('/college_info')
@login_required
def college_info():
    username = session['log_username']
    return render_template('college_info.html', name=username[0], class_name=username[1], admission_no=username[2], application_no=username[3], department=username[4], rollno=username[5])


@app.route('/fcollege_info')
@faculty_login_required
def fcollege_info():
    username = session['log_username']
    return render_template('faculty/fcollege_info.html', name=username[0], class_name=username[1], admission_no=username[2], application_no=username[3], department=username[4], rollno=username[5], id_no=username[6])


@app.route('/faculty_dashboard')
@faculty_login_required
def faculty_dashboard():
    username = session['log_username']
    return render_template('faculty/faculty_dashboard.html', name=username[0])


@app.route('/faculty_attendance')
@faculty_login_required
def faculty_attendance():
    return render_template('faculty/f_attendance.html')


@app.route('/f_upload_attendance', methods=['GET', 'POST'])
@faculty_login_required
def upload_attendance():
    atd = request.form
    jsn = json.dumps(atd)
    print(jsn)
    jsnlod = json.loads(jsn)
    print(jsnlod)
    print(jsnlod['one_radio'])
    return 'success'


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('logged-in', None)
    flash('logout successfully ')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
