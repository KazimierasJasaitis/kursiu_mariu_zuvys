from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import logging
import json
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, current_user, login_user, logout_user


# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
CORS(app,supports_credentials=True,origins=["https://localhost:4443"])

# Configure secret key
app.config['SECRET_KEY'] = 'your_secret_key'

# Optionally, if you're using Flask-Session
@app.after_request
def apply_cors(response):
    for key in ('Set-Cookie', 'set-cookie'):
        if key in response.headers:
            response.headers[key] = response.headers[key] + "; SameSite=None; Secure"
    return response

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create the SQLAlchemy db instance
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    unlocked_fishes = db.Column(db.Text, default='[]')  # Store as JSON text
    highscores = db.Column(db.JSON, default={})  # Store as JSON text

    def get_unlocked_fishes(self):
        return json.loads(self.unlocked_fishes)

    def get_highscores(self):
        if isinstance(self.highscores, str):
            # Deserialize string to JSON
            return json.loads(self.highscores)
        elif isinstance(self.highscores, dict):
            # Already a dictionary, return as is
            return self.highscores
        else:
            # Handle other types or raise an error
            raise TypeError("Highscores is not a valid JSON string or dictionary")


    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not all(key in data for key in ['username', 'email', 'password']):
            app.logger.warning('Missing username, email, or password')
            return jsonify({'message': 'Missing username, email, or password'}), 400

        if User.query.filter_by(email=data['email']).first() or User.query.filter_by(username=data['username']).first():
            app.logger.info('Email or Username already exists')
            return jsonify({'message': 'Email or Username already exists'}), 409

        new_user = User(username=data['username'], email=data['email'])
        new_user.set_password(data['password'])
        # Initialize the new fields as empty
        new_user.unlocked_fishes = json.dumps([])
        new_user.highscores = json.dumps({})
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201

    except Exception as e:
        app.logger.error(f'Registration Error: {e}')
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        app.logger.debug(f"Login Attempt with data: {data}")

        identifier = data.get('identifier')
        app.logger.debug(f"Identifier: {identifier}")

        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()

        if user:
            app.logger.debug("User found in database")
            # Correct way to check the password
            if user and check_password_hash(user.password_hash, data['password']):
                login_user(user)  # This logs in the user
                return jsonify({'message': 'Login successful', 'status': 'success'}), 200
            else:
                app.logger.debug("Password mismatch")
        else:
            app.logger.debug("User not found")

        return jsonify({'message': 'Invalid username or password'}), 401

    except Exception as e:
        app.logger.error(f'Login Error: {e}')
        return jsonify({'message': 'Internal Server Error'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    if current_user.is_authenticated:
        logout_user()
        response = jsonify({'message': 'Logged out successfully'})
        response.set_cookie('session', '', expires=0)
        return response, 200
    else:
        return jsonify({'message': 'No user is currently logged in'}), 403

@app.route('/update_score', methods=['POST'])
def update_score():
    if not current_user.is_authenticated:
        return jsonify({'message': 'User not authenticated'}), 401

    data = request.json
    fish_name = data.get('fish_name', '')  # Default to empty string if not provided
    new_score = data.get('score')

    user = User.query.get(current_user.id)

    # Deserialize highscores if it's a string
    if isinstance(user.highscores, str):
        user.highscores = json.loads(user.highscores)

    # Ensure highscores is a dictionary
    if user.highscores is None:
        user.highscores = {}

    print(f"Before update: {user.highscores}")  # Debugging

    # Initialize an empty list for a new fish
    if fish_name not in user.highscores:
        user.highscores[fish_name] = []

    # Append the new score and sort
    user.highscores[fish_name].append(new_score)
    user.highscores[fish_name] = sorted(user.highscores[fish_name], reverse=True)[:10]  # Keep only top 10 scores

    print(f"After update: {user.highscores}")  # Debugging

    # Manually serialize highscores
    user.highscores = json.dumps(user.highscores)

    db.session.commit()
    # ... after db.session.commit() ...
    updated_user = User.query.get(current_user.id)
    print(f"Database highscores: {updated_user.highscores}")

    db.session.refresh(user)
    return jsonify({'message': 'Score updated successfully'}), 200

@app.route('/top_scores', methods=['GET'])
def top_scores():
    try:
        # Get all users' usernames and highscores
        all_user_data = User.query.with_entities(User.username, User.highscores).all()

        # Aggregate scores from all users
        aggregated_scores = []
        for username, highscores in all_user_data:
            # Deserialize highscores if it's a string
            if isinstance(highscores, str):
                highscores = json.loads(highscores)

            if highscores:
                for fish, scores in highscores.items():
                    for score in scores:
                        aggregated_scores.append({'username': username, 'fish': fish, 'score': score})

        # Sort and get top 10 scores
        aggregated_scores.sort(key=lambda x: x['score'], reverse=True)
        top_10_scores = aggregated_scores[:10]

        return jsonify(top_10_scores), 200

    except Exception as e:
        app.logger.error(f'Top Scores Error: {e}')
        return jsonify({'message': 'Internal Server Error'}), 500


@app.route('/get_user_data', methods=['GET'])
def get_user_data():
    app.logger.debug(f'User authenticated: {current_user.is_authenticated}')
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        user_data = {
            'username': user.username,
            'email': user.email,
            'unlocked_fishes': user.get_unlocked_fishes(),
            'highscores': user.get_highscores()
        }
        print(user_data)
        return jsonify(user_data), 200
    else:
        return jsonify({'message': 'No user logged in'}), 401

@app.route('/unlock_fish', methods=['POST'])
def unlock_fish():
    if not current_user.is_authenticated:
        return jsonify({'message': 'User not authenticated'}), 401

    data = request.json
    unlocking_keyword = data.get('unlocking_keyword')
    print(unlocking_keyword)
    if not unlocking_keyword:
        return jsonify({'message': 'No unlocking keyword provided'}), 400

    # Define your keyword-to-fish mapping here
    fish_mapping = {
        'starkis': 'starkis',
        'auksle': 'auksle',
        'settingsFish': 'nustatymzuve',
        'HIDDENFISH': 'eserys',
        'highscore_5': 'dygle',
        'highscore_30': 'dygle',
        'highscore_50': 'banginisNX',
    }

    fish_name = fish_mapping.get(unlocking_keyword)
    if not fish_name:
        return jsonify({'message': 'Invalid unlocking keyword'}), 400

    user = User.query.get(current_user.id)

    # Deserialize unlocked_fishes if it's a string
    if isinstance(user.unlocked_fishes, str):
        user.unlocked_fishes = json.loads(user.unlocked_fishes)

    # Ensure unlocked_fishes is a list
    if user.unlocked_fishes is None:
        user.unlocked_fishes = []

    # Add new fish if it's not already unlocked
    if fish_name not in user.unlocked_fishes:
        user.unlocked_fishes.append(fish_name)

        # Serialize back to JSON for storage
        user.unlocked_fishes = json.dumps(user.unlocked_fishes)

        db.session.commit()
        return jsonify({'message': f'{fish_name} unlocked successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True, ssl_context=("selfsigned.crt", "private.key"), host='0.0.0.0', port=5000)

