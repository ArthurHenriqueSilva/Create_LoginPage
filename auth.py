from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db

auth = Blueprint('auth', __name__)
@auth.route('/login', methods=['GET', 'POST'])
def login():
    rf = request.form
    if request.method == 'GET':
        return render_template('login.html')
    else:
        email = rf.get('email')
        password = rf.get('password')
        remember = True if rf.get('remember') else False
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Please sign up before!')
            return redirect(url_for('auth.signup'))
        elif not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))
        login_user(user, remember=remember)
        return redirect(url_for('main.profile'))
    

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    rf = request.form
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        email = rf.get('email')
        name = rf.get('name')
        password = rf.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))
        new_user = User(email=email, name=name, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))



@auth.route('/show_users_page')
@login_required
def show_users_page():
    return render_template('show_users_page.html')


@auth.route('/show_users', methods=['GET', 'POST'])
@login_required
def show_users():
    rf = request.form

    admin_password = rf.get('admin_password')
    admin_user = User.query.filter_by(name="admin").first()
    if admin_user:
        if check_password_hash(admin_user.password, admin_password):
            all_users = User.query.all()
            user_list = [{'id':user.id, 'email':user.email, 'name':user.name} for user in all_users]
            return jsonify(users=user_list)
        else:
            return jsonify(error='Authentication Failed'), 401