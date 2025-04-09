import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, send, emit
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Message
import requests
import httpx

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

online_users = set()
tables_created = False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_tables():
    global tables_created
    if not tables_created:
        db.create_all()
        tables_created = True

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('chat'))

        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', username=current_user.username, messages=messages)

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        online_users.add(current_user.username)
        emit('user_list', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        online_users.discard(current_user.username)
        emit('user_list', list(online_users), broadcast=True)

@socketio.on('message')
def handle_message(msg):
    text = msg['text']
    if text.startswith('/gif '):
        query = text[5:]
        try:
            response = httpx.get(
                f'https://api.giphy.com/v1/gifs/search',
                params={
                    'api_key': 'xvIAbtoVihHfwvmgMUtZChgAAaypPq42',
                    'q': query,
                    'limit': 1,
                    'rating': 'R'
                },
                timeout=5
            )
            data = response.json()
            if data['data']:
                gif_url = data['data'][0]['images']['downsized']['url']
                text = f'<img src="{gif_url}" width="200">'
            else:
                text = 'GIF not found!'
        except Exception as e:
            print(f"Giphy error: {e}")
            text = 'GIF fetch failed!'

    message = Message(username=current_user.username, text=text, user_id=current_user.id)
    db.session.add(message)
    db.session.commit()

    emit('message', {
        'id': message.id,
        'username': current_user.username,
        'text': text,
    }, broadcast=True)

@app.route('/edit_message/<int:message_id>', methods=['POST'])
@login_required
def edit_message(message_id):
    msg = Message.query.get_or_404(message_id)
    if msg.user_id != current_user.id:
        return 'Unauthorized', 403

    new_text = request.json.get('text', '')
    msg.text = new_text
    db.session.commit()
    socketio.emit('edit_message', {'id': msg.id, 'text': new_text})
    return 'OK', 200

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = Message.query.get_or_404(message_id)
    if msg.user_id != current_user.id:
        return 'Unauthorized', 403

    db.session.delete(msg)
    db.session.commit()
    socketio.emit('delete_message', {'id': message_id})
    return 'OK', 200

if __name__ == '__main__':
    socketio.run(app, debug=True)
