from flask import Blueprint, render_template, current_app, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
import logging
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
            flash('Os dados estao incorretos ou ainda nao nos conhecemos!!')
            return redirect(url_for('auth.signup'))
        elif not check_password_hash(user.password, password):
            flash('Cheque os dados inseridos e tente novamente!.')
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
            flash('Esse e-mail ja esta sendo utilizado.')
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


@auth.route('/show_users', methods=['POST', 'GET'])
@login_required
def show_users():
    if current_user.name == "admin" and current_user.email == "admin@admin.com":
        all_users = User.query.all()
        user_list = [{'id': user.id, 'email': user.email, 'name': user.name} for user in all_users]

        if request.method == 'POST':
            return jsonify(users=user_list)
        else:
            return render_template('show_users_page.html', data={'users': user_list})
    else:
        return jsonify(error='Autenticacao falhou!'), 401
    


@auth.route('/delete_user', methods=['POST', 'GET'])
@login_required
def delete_user():
    if current_user.name != 'admin':
        flash('Permission denied. Only admin can delete users.')
        return redirect(url_for('main.index'))

    if request.method == 'GET':
        all_users = User.query.filter(User.name != 'admin').all()
        user_list = [{'id': user.id, 'email': user.email, 'name': user.name} for user in all_users]
        return render_template('delete_user_page.html', data={'users': user_list})

    elif request.method == 'POST':
        users_to_delete = request.form.getlist('users_to_delete[]')

        if not users_to_delete:
            flash('Nao existe usuarios para serem deletados!')
            return redirect(url_for('auth.delete_user'))

        try:
            for user_id in users_to_delete:
                user_to_delete = User.query.get(int(user_id))
                if user_to_delete:
                    db.session.delete(user_to_delete)
            db.session.commit()
        except Exception as e:
            flash(f'An error occurred during deletion: {e}')

        return redirect(url_for('main.index'))