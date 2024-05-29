#!/bin/bash

# Function to print messages
print_message() {
    echo "-------------------------------------"
    echo $1
    echo "-------------------------------------"
}

# Print starting message
print_message "Starting setup of JWT-based TODO Flask application with SQLite"

# Update package list and install Python3 and pip if not installed
if ! command -v python3 &> /dev/null
then
    print_message "Python3 is not installed. Installing Python3..."
    apt-get update
    apt-get install -y python3 python3-pip
else
    print_message "Python3 is already installed"
fi

# Create todos-flask folder and enter it
mkdir todos-flask
cd todos-flask

# Install virtualenv if not installed
if ! command -v virtualenv &> /dev/null
then
    print_message "virtualenv is not installed. Installing virtualenv..."
    pip3 install virtualenv
else
    print_message "virtualenv is already installed"
fi

# Create a virtual environment
print_message "Creating a virtual environment"
virtualenv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
print_message "Installing dependencies"
pip install Flask Flask-JWT-Extended Flask-SQLAlchemy Flask-Migrate bcrypt

# Create necessary folders and files
print_message "Creating necessary folders and files"
mkdir -p app
cd app
touch __init__.py models.py routes.py

# Add Flask app configuration in __init__.py
print_message "Adding Flask app configuration"
cat <<EOT > __init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

from app import routes, models
EOT

# Add models in models.py
print_message "Adding models"
cat <<EOT > models.py
from app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    todo = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('todos', lazy=True))
EOT

# Add routes in routes.py
print_message "Adding routes"
cat <<EOT > routes.py
from app import app, db
from app.models import User, Todo
from flask import request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import bcrypt

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    user = User(username=username, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify(message="User registered"), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify(message="Invalid credentials"), 401

@app.route('/todos', methods=['GET', 'POST'])
@jwt_required()
def manage_todos():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.get_json()
        todo = Todo(user_id=user_id, todo=data['todo'], completed=data.get('completed', False))
        db.session.add(todo)
        db.session.commit()
        return jsonify(message="Todo item added"), 201
    else:
        todos = Todo.query.filter_by(user_id=user_id).all()
        return jsonify([{
            'id': todo.id,
            'todo': todo.todo,
            'completed': todo.completed,
            'created_at': todo.created_at,
            'updated_at': todo.updated_at
        } for todo in todos]), 200

@app.route('/todos/<int:todo_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_todo(todo_id):
    user_id = get_jwt_identity()
    todo = Todo.query.filter_by(id=todo_id, user_id=user_id).first()
    if not todo:
        return jsonify(message="Todo item not found"), 404

    if request.method == 'PUT':
        data = request.get_json()
        todo.todo = data.get('todo', todo.todo)
        todo.completed = data.get('completed', todo.completed)
        db.session.commit()
        return jsonify(message="Todo item updated"), 200
    else:
        db.session.delete(todo)
        db.session.commit()
        return jsonify(message="Todo item deleted"), 200
EOT

# Initialize the database and run migrations
print_message "Initializing the database and running migrations"
cd ..
export FLASK_APP=app
flask db init
flask db migrate -m "Initial migration."
flask db upgrade

# Run the server
print_message "Starting the server"
flask run
