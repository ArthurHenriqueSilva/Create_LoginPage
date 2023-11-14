from flask import Blueprint, render_template, flash
from flask_login import login_required, current_user


main = Blueprint('main', __name__)

@main.route('/')
def index():
    return 'index'

@main.route('/profile')
def profile():
    return 'profile'


if(__name__ == '__main__'):
    from __init__ import create_app, db
    app = create_app()
    with app.app_context():
        db.create_all()

    app.run(debug=True)