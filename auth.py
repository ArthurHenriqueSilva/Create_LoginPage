from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user
from __init__ import db

auth = Blueprint('auth', __name__)
@auth.route('/login', methods=['GET'])
def login():
    return 'login'

@auth.route('/signup', methods=['GET'])
def signup():
    return 'signup'

@auth.route('/logout')
def logout():
    return 'logout'

