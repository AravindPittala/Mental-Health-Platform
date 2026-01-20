from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os, toml

import requests, os, toml
from peacepal import peacepal_app  # Import Peace Pal Blueprint

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure secret key

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Register PeacePal Blueprint
app.register_blueprint(peacepal_app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password!", 'error')  # Flash error message
        
    return render_template('login.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", 'error')  # Flash error message
            return render_template('signup.html')

        # Hash the password before saving
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred: {e}", 'error')  # Flash error message
            return render_template('signup.html')

    return render_template('signup.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("You need to be logged in to view the dashboard", 'error')
        return redirect(url_for('login'))

    return render_template('dashboard.html', username=session['username'])

# About Us route
@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')  # Ensure aboutus.html is in the templates folder


@app.route('/contact')
def contact():
    return render_template('contact.html')



# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash("You have been logged out.", 'success')  # Flash success message
    return redirect(url_for('home'))

# Self-Assessment Test Route using Groq API
@app.route('/self-assessment', methods=['GET', 'POST'])
def self_assessment():
    if request.method == 'POST':
        responses = request.form.getlist('response[]')
        feedback, solutions = analyze_responses(responses)
        session['feedback'] = feedback
        session['solutions'] = solutions
        return redirect(url_for('results'))

    # Generate questions using Groq API
    import os, toml

    api_file = os.path.join(os.path.dirname(__file__), "key.toml")
    api_key = toml.load(api_file)['api']['key']
    questions = generate_questions(api_key)
    return render_template('self_assessment.html', questions=questions)

def generate_questions(api_key):
    payload = {
        "model": "llama-3.1-8b-instant",
        'messages': [{'role': 'system', 'content': 'Generate 10 self-assessment questions for mental health. and also diagnose based on the output recieved and tell their mental health issue or illness they are facing '}],
        'max_tokens': 150
    }
    response = requests.post(
        
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'},
        json=payload
    )
    content = response.json().get('choices', [{}])[0].get('message', {}).get('content', '')
    return content.strip().split('\n')

def analyze_responses(responses):
    score = 0
    for response in responses:
        if response in ["Often", "Always", "4", "5"]:
            score += 2
        elif response in ["Sometimes", "3"]:
            score += 1
        elif response in ["Rarely", "Never", "1", "2"]:
            score += 0
    
    if score >= 15:
        feedback = "You may be experiencing significant mental health challenges. It's important to seek professional help."
        solutions = [
            "Consider reaching out to a mental health professional.",
            "Practice mindfulness and relaxation techniques daily.",
            "Engage in regular physical activity to improve mood."
        ]
    elif score >= 8:
        feedback = "You may be experiencing some mental health challenges. It's a good idea to talk to someone you trust."
        solutions = [
            "Talk to a friend or family member about how you're feeling.",
            "Try journaling to express your thoughts and emotions.",
            "Establish a consistent sleep routine to improve rest."
        ]
    else:
        feedback = "Your mental health seems to be in good shape. Keep up the good work!"
        solutions = [
            "Continue practicing self-care and mindfulness.",
            "Stay connected with friends and loved ones.",
            "Engage in activities that bring you joy and relaxation."
        ]
    
    return feedback, solutions

# Results route
@app.route('/results')
def results():
    feedback = session.get('feedback', 'No feedback available.')
    solutions = session.get('solutions', [])
    return render_template('results.html', feedback=feedback, solutions=solutions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initialize database tables
    app.run(debug=True)