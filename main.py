from flask import Blueprint, render_template, flash
from flask_login import login_required, current_user


main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html', auth=current_user)

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)


if(__name__ == '__main__'):
    from __init__ import create_app, db
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True) 