import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cf4317eea222283e6c4c771a15d291e6c193fbb098716a735fff8960bcb35719'


# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# TODO 1:  configure your Flask app to use Flask_Login.
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB


class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


# TODO 2: create a user loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You have already registerd")
            return redirect(url_for('login'))
        # TODO 4: check the user password using hash function
        hash_salted_password = generate_password_hash(request.form.get('password'),
                                                      method='pbkdf2:sha256', salt_length=8
                                                      )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_salted_password

        )
        db.session.add(new_user)
        db.session.commit()

        return render_template('secrets.html', new_user=new_user)
    return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # TODO 5: find the user by the email they entered in the login form (e.g., with a where clause).
        user_by_email = User.query.filter_by(email=email).first()  # <--SQLAlchemy ORM style  this is SQLALCHEMY
        # CORE-->( style db.session.execute(db.select(User).where(User.email == email).first())

        # TODO 6: check if the user exists and if their password is correct. If they are, log them in and redirect to
        #  the secrets page.
        if user_by_email and check_password_hash(user_by_email.password, password):
            login_user(user_by_email, remember=True)
            flash("login successful")
            return redirect(url_for('secrets'))
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", new_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(
        '/static/files', 'cheat_sheet.pdf', as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
