import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '*123*ubothered')

# Set up SQLAlchemy database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')


# Create SQLAlchemy database model base
class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Create User model
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


# Create database tables
with app.app_context():
    db.create_all()


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Using the updated SQLAlchemy 2.x API


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Check if the email is already registered
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You have already registered")
            return redirect(url_for('login'))

        # Hash password
        hash_salted_password = generate_password_hash(
            request.form.get('password'), method='pbkdf2:sha256', salt_length=8)

        # Create new user
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return render_template('secrets.html')
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user by email
        user_by_email = User.query.filter_by(email=email).first()

        # Check password and log in user
        if user_by_email and check_password_hash(user_by_email.password, password):
            login_user(user_by_email, remember=True)
            flash("Login successful")
            return redirect(url_for('secrets'))
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))
    return render_template("login.html", logged_in = current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", new_user=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    # Use the correct path to static directory for file download
    return send_from_directory(app.static_folder + '/files', 'cheat_sheet.pdf', as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
