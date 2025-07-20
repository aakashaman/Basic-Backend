from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import jwt
import datetime
import logging
import os

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

# Configure CORS
CORS(app, resources={r"/api/*": {"origins": "https://basicfront-three.vercel.app"}}, supports_credentials=True)

db = SQLAlchemy(app)

# Log database engine
with app.app_context():
    logger.debug(f"Database engine: {db.engine.url}")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length to 255

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Middleware to log response headers
@app.after_request
def add_cors_headers(response):
    logger.debug(f"Response Headers: {response.headers}")
    return response

# Middleware to verify JWT token
def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            logger.debug("No token provided")
            return jsonify({'error': 'Token is missing'}), 401
        try:
            token = token.split(" ")[1]  # Expecting "Bearer <token>"
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                logger.debug("User not found for token")
                return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json(force=True)
        username = data.get('username')
        password = data.get('password')

        logger.debug(f"Register attempt with username: {username}")

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password are required'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        logger.debug(f"User {username} registered successfully")
        return jsonify({'success': True})
    except ValueError as e:
        logger.error(f"Invalid JSON: {str(e)}")
        return jsonify({'success': False, 'message': f'Invalid JSON: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json(force=True)
        username = data.get('username')
        password = data.get('password')

        logger.debug(f"Login attempt with username: {username}")

        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password are required'}), 400

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            logger.debug(f"User {username} logged in successfully")
            return jsonify({'success': True, 'token': token, 'user': {'username': user.username}})
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    except ValueError as e:
        logger.error(f"Invalid JSON: {str(e)}")
        return jsonify({'success': False, 'message': f'Invalid JSON: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/check-auth', methods=['GET'])
@token_required
def check_auth(current_user):
    logger.debug(f"Auth check: User {current_user.username} is authenticated")
    return jsonify({'isAuthenticated': True, 'user': {'username': current_user.username}})

@app.route('/api/todos', methods=['GET', 'POST'])
@token_required
def todos(current_user):
    if request.method == 'GET':
        todos = Todo.query.filter_by(user_id=current_user.id).all()
        logger.debug(f"Fetched {len(todos)} todos for user_id {current_user.id}")
        return jsonify([{'id': todo.id, 'task': todo.task} for todo in todos])

    if request.method == 'POST':
        try:
            data = request.get_json(force=True)
            task = data.get('task')
            if not task:
                logger.debug("Task is required")
                return jsonify({'success': False, 'message': 'Task is required'}), 400
            new_todo = Todo(task=task, user_id=current_user.id)
            db.session.add(new_todo)
            db.session.commit()
            logger.debug(f"Added todo: {task}")
            return jsonify({'id': new_todo.id, 'task': new_todo.task})
        except ValueError as e:
            logger.error(f"Invalid JSON: {str(e)}")
            return jsonify({'success': False, 'message': f'Invalid JSON: {str(e)}'}), 400
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/todos/<int:id>', methods=['PUT', 'DELETE'])
@token_required
def todo(current_user, id):
    todo = Todo.query.filter_by(id=id, user_id=current_user.id).first()
    if not todo:
        logger.debug(f"Todo {id} not found for user_id {current_user.id}")
        return jsonify({'error': 'Todo not found'}), 404

    if request.method == 'PUT':
        try:
            data = request.get_json(force=True)
            task = data.get('task')
            if not task:
                logger.debug("Task is required for update")
                return jsonify({'success': False, 'message': 'Task is required'}), 400
            todo.task = task
            db.session.commit()
            logger.debug(f"Updated todo {id}: {task}")
            return jsonify({'id': todo.id, 'task': todo.task})
        except ValueError as e:
            logger.error(f"Invalid JSON: {str(e)}")
            return jsonify({'success': False, 'message': f'Invalid JSON: {str(e)}'}), 400
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

    if request.method == 'DELETE':
        db.session.delete(todo)
        db.session.commit()
        logger.debug(f"Deleted todo {id}")
        return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Drop existing tables to fix schema issues
        db.create_all()  # Create tables with correct schema
        logger.debug("Database tables created")
    app.run(debug=True)