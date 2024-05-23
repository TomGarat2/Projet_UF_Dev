from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
from datetime import datetime
from Crypto.Random import get_random_bytes
import pyotp
from flask import session
from flask_talisman import Talisman
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'une_clef_secrete_tres_securisee'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_password'

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

Talisman(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    keys = db.Column(db.Text, nullable=False, default='')
    otp_secret = db.Column(db.String(16))
    role = db.Column(db.String(10), default='user')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    file_path = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Length(min=6, max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password should be at least %(min)d characters long'),
        Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)', message='Password must contain one lowercase letter, one uppercase letter, one digit, and one special character')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=6, max=120)])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password should be at least %(min)d characters long'),
        Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)', message='Password must contain one lowercase letter, one uppercase letter, one digit, and one special character')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

def encrypt_key(key):
    master_key = os.environ.get('MASTER_KEY', 'your_master_key_here').encode()
    salt = os.urandom(16)
    kdf = PBKDF2(master_key, salt, dkLen=32, count=100000)
    cipher = AES.new(kdf, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(key.encode())
    encrypted_key = b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')
    return encrypted_key

def decrypt_key(encrypted_key):
    master_key = os.environ.get('MASTER_KEY', 'your_master_key_here').encode()
    data = b64decode(encrypted_key)
    salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
    kdf = PBKDF2(master_key, salt, dkLen=32, count=100000)
    cipher = AES.new(kdf,AES.MODE_EAX, nonce=nonce)
    decrypted_key = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    return decrypted_key

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already taken. Please choose a different one.', 'danger')
            return render_template('register.html', title='Register', form=form)
        email_user = User.query.filter_by(email=form.email.data).first()
        if email_user is not None:
            flash('Email already registered. Please use a different one.', 'danger')
            return render_template('register.html', title='Register', form=form)
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, keys='')
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Your account has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/")
@login_required
def home():
    return render_template('home.html')

@app.route('/encrypt_decrypt')
@login_required
def encrypt_decrypt():
    return render_template('encrypt_decrypt.html')

@app.route('/encrypt', methods=['POST'])
@login_required
def encrypt():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        original_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(original_path)
        key = get_random_bytes(16)  # Generating a 128-bit key
        encrypted_key = encrypt_key(key.hex())
        with open(original_path, 'rb') as f:
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(f.read())
        encrypted_path = original_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
        # Save file info to the database
        new_file = File(user_id=current_user.id, filename=filename + '.enc', file_path=encrypted_path, uploaded_at=datetime.utcnow())
        db.session.add(new_file)
        # Append the encrypted key to the user's keys
        current_user.keys += encrypted_key + ';'
        db.session.commit()
        os.remove(original_path)  # Remove the original unencrypted file
        return redirect(url_for('encrypt_success', key=encrypted_key))
    return redirect(url_for('encrypt_decrypt'))

@app.route('/encrypt_success')
@login_required
def encrypt_success():
    key = request.args.get('key')
    return render_template('encrypt_success.html', key=key)

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt():
    file = request.files['file']
    encrypted_key = request.form['key']
    key = decrypt_key(encrypted_key)
    if file and key:
        filename = secure_filename(file.filename)
        encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
        if not encrypted_path.endswith('.enc'):
            return jsonify('Invalid file. It must be a .enc file')
        with open(encrypted_path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
            cipher = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
            try:
                data = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                return jsonify('Decryption failed, incorrect key or corrupted file')
        decrypted_filename = 'decrypted_' + filename.replace('.enc', '')
        decrypted_path = os.path.join(UPLOAD_FOLDER, decrypted_filename)
        with open(decrypted_path, 'wb') as f:
            f.write(data)
        # Save decrypted file info to the database
        new_file = File(user_id=current_user.id, filename=decrypted_filename, file_path=decrypted_path, uploaded_at=datetime.utcnow())
        db.session.add(new_file)
        db.session.commit()
        return redirect(url_for('decrypt_success', filename=decrypted_filename))
    return redirect(url_for('encrypt_decrypt'))

@app.route('/decrypt_success')
@login_required
def decrypt_success():
    filename = request.args.get('filename')
    return render_template('decrypt_success.html', filename=filename)

@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/files')
@login_required
def list_files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('files.html', files=files)

@app.route('/files/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('Unauthorized to access this file.', 'danger')
        return redirect(url_for('list_files'))
    return send_from_directory(UPLOAD_FOLDER, file.filename)

@app.route('/files/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('Unauthorized to access this file.', 'danger')
        return redirect(url_for('list_files'))
    os.remove(os.path.join(UPLOAD_FOLDER, file.filename))
    db.session.delete(file)
    db.session.commit()
    flash('File successfully deleted.', 'success')
    return redirect(url_for('list_files'))

@app.route('/key_history')
@login_required
def key_history():
    keys = current_user.keys.split(';') if current_user.keys else []
    return render_template('key_history.html', keys=keys)

@app.route('/generate_otp')
@login_required
def generate_otp():
    user = current_user
    user.otp_secret = pyotp.random_base32()
    db.session.commit()
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(user.username, issuer_name="YourAppName")
    return jsonify({'otp_uri': otp_uri})

@app.route('/verify_otp', methods=['POST'])
@login_required
def verify_otp():
    otp = request.form.get('otp')
    if pyotp.TOTP(current_user.otp_secret).verify(otp):
        session['otp_verified'] = True
        return redirect(url_for('home'))
    else:
        flash('Invalid OTP', 'danger')
        return redirect(url_for('login'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='email-reset')
            msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[user.email])
            link = url_for('reset_password_token', token=token, _external=True)
            msg.body = f'Your link to reset your password is {link}. If you did not request this, please ignore this email.'
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found. Please check and try again.', 'danger')
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = s.loads(token, salt='email-reset', max_age=3600)
    except SignatureExpired:
        flash('The token is expired. Please try again.', 'danger')
        return redirect(url_for('reset_password_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        hashed_password = generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been reset. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

csp = {
    'default-src': [
        '\'self\'',
        'https://trusted-cdn.com'
    ],
    'img-src': '*',
    'script-src': [
        '\'self\'',
        'https://trusted-cdn.com'
    ],
}

Talisman(app, content_security_policy=csp)


if __name__ == '__main__':
    if os.path.exists('site.db'):
        os.remove('site.db')  # Remove the existing database file
    with app.app_context():
        db.create_all()  # Create all database tables
    app.run(debug=True)
