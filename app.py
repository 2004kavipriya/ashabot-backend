from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import sqlite3
import os
import hashlib
import jwt
import datetime
import google.generativeai as genai
from functools import wraps

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Make sure this matches JWT_SECRET_KEY

# Initialize JWT
jwt_manager = JWTManager(app)

# Configure Gemini API with the new key
GEMINI_API_KEY = 'AIzaSyCfsnqzGy14RnjPzg07rqWHAvazPCoZJJI'
genai.configure(api_key=GEMINI_API_KEY)

# Initialize model - directly use the specific model we need
try:
    print('Listing available models...')
    for m in genai.list_models():
        print(m.name)
    print('Initializing Gemini model...')
    model = genai.GenerativeModel('models/gemini-1.5-flash-8b-latest')
    test_response = model.generate_content('Hello')
    print('Gemini API configured successfully')
except Exception as e:
    print('Error configuring Gemini API:', str(e))
    model = None

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in the header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # Get user from database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id, username FROM users WHERE username = ?', (data['username'],))
            current_user = cursor.fetchone()
            conn.close()
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Check if required fields are provided
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username']
    password = data['password']
    
    # Hash the password for security
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    
    # Insert new user
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                      (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    username = data['username']
    password = data['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, hashed_password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        access_token = create_access_token(identity=username)
        return jsonify({
            'token': access_token,
            'username': username
        }), 200
    
    return jsonify({'error': 'Invalid username or password'}), 401

# Chat history endpoints
@app.route('/api/chats', methods=['GET'])
@jwt_required()
def get_chats():
    current_user_id = get_jwt_identity()
    chats = Chat.query.filter_by(user_id=current_user_id).order_by(Chat.timestamp.desc()).all()
    return jsonify([{
        'id': chat.id,
        'title': chat.title,
        'timestamp': chat.timestamp.isoformat(),
        'messages': [{
            'text': msg.text,
            'isUser': msg.is_user,
            'wasVoice': msg.was_voice,
            'timestamp': msg.timestamp.isoformat()
        } for msg in chat.messages]
    } for chat in chats])

@app.route('/api/chats', methods=['POST'])
@jwt_required()
def create_chat():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    new_chat = Chat(
        id=data['id'],
        title=data['title'],
        timestamp=datetime.datetime.fromisoformat(data['timestamp']),
        user_id=current_user_id
    )
    
    for msg_data in data.get('messages', []):
        message = Message(
            text=msg_data['text'],
            is_user=msg_data['isUser'],
            was_voice=msg_data.get('wasVoice', False)
        )
        new_chat.messages.append(message)
    
    db.session.add(new_chat)
    db.session.commit()
    return jsonify({'message': 'Chat created successfully'})

@app.route('/api/chats/<chat_id>', methods=['PUT'])
@jwt_required()
def update_chat_endpoint(chat_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if save_chat(user_id, chat_id, data['title'], data['messages']):
        return jsonify({'message': 'Chat updated successfully'})
    return jsonify({'error': 'Failed to update chat'}), 500

@app.route('/api/chats/<chat_id>', methods=['DELETE'])
@jwt_required()
def delete_chat_endpoint(chat_id):
    user_id = get_jwt_identity()
    if delete_chat(user_id, chat_id):
        return jsonify({'message': 'Chat deleted successfully'})
    return jsonify({'error': 'Failed to delete chat'}), 500

@app.route('/api/chat', methods=['POST'])
@jwt_required()
def chat():
    user_id = get_jwt_identity()
    print(f'Received chat request from user: {user_id}')
    try:
        # Check if Gemini API is configured
        if model is None:
            return jsonify({
                'error': 'AI service is currently unavailable'
            }), 503

        # Get request data
        data = request.get_json()
        message = data.get('message')
        chat_id = data.get('chatId')
        is_voice_input = data.get('isVoiceInput', False)
        
        if not message:
            return jsonify({'error': 'Message is required'}), 400
        
        try:
            # Add context based on input type
            if is_voice_input:
                prompt = f"User spoke: {message}\nRespond in a natural, conversational way suitable for voice interaction."
            else:
                prompt = f"User wrote: {message}\nRespond in a clear and helpful way."
            
            # Generate response using Gemini
            response = model.generate_content(prompt)
            
            # Extract text from response
            response_text = ""
            if hasattr(response, 'text'):
                response_text = response.text
            elif hasattr(response, 'parts'):
                for part in response.parts:
                    if hasattr(part, 'text'):
                        response_text += part.text
            
            if response_text:
                return jsonify({
                    'response': response_text,
                    'chatId': chat_id
                })
            else:
                return jsonify({
                    'error': 'Failed to generate response'
                }), 500
                
        except Exception as e:
            print('Error generating response:', str(e))
            return jsonify({'error': 'Failed to generate response'}), 500
            
        except Exception as e:
            print('Error generating response:', str(e))
            return jsonify({
                'message': f'I apologize, but I encountered an error processing your {input_type} input. Please try again later.',
                'error': str(e)
            }), 200
            
    except Exception as e:
        print('Server error:', str(e))
        return jsonify({
            'message': 'I apologize, but I encountered a server error. Please try again later.',
            'error': str(e)
        }), 200

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        current_user = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID
        cursor.execute('SELECT id FROM users WHERE username = ?', (current_user,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Get profile data
        cursor.execute('SELECT * FROM profiles WHERE user_id = ?', (user['id'],))
        profile = cursor.fetchone()
        conn.close()
        
        if profile:
            return jsonify({
                'name': profile['name'],
                'email': profile['email'],
                'phone': profile['phone'],
                'location': profile['location'],
                'skills': profile['skills'].split(',') if profile['skills'] else [],
                'experience': eval(profile['experience']) if profile['experience'] else [],
                'education': eval(profile['education']) if profile['education'] else [],
                'achievements': eval(profile['achievements']) if profile['achievements'] else [],
                'certifications': eval(profile['certifications']) if profile['certifications'] else [],
                'links': eval(profile['links']) if profile['links'] else {},
                'profile_photo': profile['profile_photo']
            })
        return jsonify({})
    except Exception as e:
        print('Error in get_profile:', str(e))
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/profile', methods=['POST'])
@jwt_required()
def save_profile():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID
        cursor.execute('SELECT id FROM users WHERE username = ?', (current_user,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Convert lists and dictionaries to strings for storage
        profile_data = {
            'name': data.get('name', ''),
            'email': data.get('email', ''),
            'phone': data.get('phone', ''),
            'location': data.get('location', ''),
            'skills': ','.join(data.get('skills', [])),
            'experience': str(data.get('experience', [])),
            'education': str(data.get('education', [])),
            'achievements': str(data.get('achievements', [])),
            'certifications': str(data.get('certifications', [])),
            'links': str(data.get('links', {})),
            'profile_photo': data.get('profile_photo', '')
        }
        
        # Check if profile exists
        cursor.execute('SELECT id FROM profiles WHERE user_id = ?', (user['id'],))
        existing_profile = cursor.fetchone()
        
        if existing_profile:
            # Update existing profile
            placeholders = ', '.join(f'{k} = ?' for k in profile_data.keys())
            query = f'UPDATE profiles SET {placeholders} WHERE user_id = ?'
            cursor.execute(query, (*profile_data.values(), user['id']))
        else:
            # Create new profile
            placeholders = ', '.join(['?'] * len(profile_data))
            columns = ', '.join(['user_id'] + list(profile_data.keys()))
            query = f'INSERT INTO profiles ({columns}) VALUES ({placeholders})'
            cursor.execute(query, (user['id'], *profile_data.values()))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Profile saved successfully'})
    except Exception as e:
        print('Error in save_profile:', str(e))
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Make sure the database exists
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Create profile table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT,
            email TEXT,
            phone TEXT,
            location TEXT,
            skills TEXT,
            experience TEXT,
            education TEXT,
            achievements TEXT,
            certifications TEXT,
            links TEXT,
            profile_photo TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    
    app.run(debug=True)