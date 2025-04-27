from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'file_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')

# ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def get_id(self):
        return str(self.user_id)

class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.String(500))

class File(db.Model):
    __tablename__ = 'files'
    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    upload_date = db.Column(db.DateTime, server_default=db.func.now())
    storage_path = db.Column(db.String(500), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'))

    user = db.relationship('User', backref=db.backref('files', lazy=True))
    category = db.relationship('Category', backref=db.backref('files', lazy=True))

with app.app_context():
    db.drop_all()  # Drop existing tables to update schema
    db.create_all()

    # create superuser if none
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('admin', method='pbkdf2:sha256'), first_name='Admin', last_name='User')
        db.session.add(admin)
        db.session.commit()

@app.route("/", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('upload_file'))
        # invalid login
        error = 'Invalid login credentials or account does not exist.'
        return render_template("login.html", error=error)
    return render_template("login.html")

@app.route("/register", methods=['GET','POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        # password match check
        if password != confirm:
            error = 'Passwords do not match.'
            return render_template('register.html', error=error, first_name=first_name, last_name=last_name, username=username, email=email)
        # uniqueness check
        if User.query.filter((User.username==username)|(User.email==email)).first():
            error = 'Username or email already exists.'
            return render_template('register.html', error=error, first_name=first_name, last_name=last_name, username=username, email=email)
        new_user = User(username=username, email=email, password_hash=generate_password_hash(password, method='pbkdf2:sha256'), first_name=first_name, last_name=last_name)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        # handle account deletion
        if 'delete_account' in request.form:
            delete_password = request.form.get('delete_password')
            if not check_password_hash(current_user.password_hash, delete_password):
                error = 'Incorrect password.'
                return render_template('account.html', error=error, user=current_user)
            db.session.delete(current_user)
            db.session.commit()
            logout_user()
            return redirect(url_for('login'))
        username = request.form.get('username')
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        # ensure new username is unique
        if User.query.filter(User.username==username, User.user_id!=current_user.user_id).first():
            error = 'Username already exists.'
            return render_template('account.html', error=error, user=current_user)
        if password:
            if password != confirm:
                error = 'Passwords do not match.'
                return render_template('account.html', error=error, user=current_user)
            current_user.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        current_user.username = username
        current_user.email = email
        current_user.first_name = first_name
        current_user.last_name = last_name
        db.session.commit()
        return redirect(url_for('upload_file'))
    return render_template('account.html', user=current_user)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            return 'No file selected'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        new_file = File(user_id=current_user.user_id, filename=file.filename, file_type=file.filename.rsplit('.',1)[-1], file_size=os.path.getsize(filepath), storage_path=filepath)
        db.session.add(new_file)
        db.session.commit()
        return 'File uploaded!'
    return render_template('dashboard.html')

if __name__ == "__main__":
    app.run(debug=True)
