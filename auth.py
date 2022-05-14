from flask import Blueprint, render_template, redirect, url_for, request, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db
import hashlib
from email.message import EmailMessage


# create a Blueprint object that we name 'auth'
auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Please sign up before!')
            return redirect(url_for('auth.signup'))
        elif not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))

        login_user(user, remember=remember)
        return redirect(url_for('auth.otp'))


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))
        new_user = User(email=email, name=name, password=generate_password_hash(
            password, method='sha256'))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))


@auth.route('/otp', methods=['GET', 'POST'])
@login_required
def otp():
    if request.method == 'GET':
        code = generateOTP(current_user.email)

        resp = make_response(render_template('otp.html'))
        resp.set_cookie('userOTP', code)

        return resp
    else:
        code = request.cookies.get('userOTP')
        otpInput = request.form.get('otp')
        inputHash = hashlib.sha256(otpInput.encode('utf-8')).hexdigest()
        if inputHash == code:
            return redirect(url_for('main.profile'))
        else:
            return redirect(url_for('auth.logout'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


def generateOTP(userEmail):
    import os
    import math
    import random
    import smtplib
    digits = "0123456789"
    OTP = ""
    for i in range(6):
        OTP += digits[math.floor(random.random()*10)]

    s = smtplib.SMTP('smtp.gmail.com', 587)
    s.starttls()
    s.login("aguasfelipe02@gmail.com", "wxoalscknmrddeeo")

    mensaje = """
    Hola!
    Te enviamos un codigo de unico uso para que puedas iniciar sesion en ECI-Login

    Codigo: {}

    Enviado desde ECILogin
    """.format(OTP)

    msg = EmailMessage()
    msg['Subject'] = 'EciLogin OTP'
    msg['From'] = 'EciLogin'
    msg['To'] = userEmail
    msg.set_content(mensaje)

    s.sendmail("EciLogin", userEmail, msg.as_bytes())
    return hashlib.sha256(OTP.encode('utf-8')).hexdigest()
