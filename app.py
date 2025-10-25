from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps # We need this for our login decorator

# --- Updated Model Imports ---
from models import db, User, Complaint 

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = 'your-very-secret-key-change-this' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/locality_issue_hub'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Database ---
db.init_app(app)

# --- NEW: Login Required Decorator ---
# This is a small helper function (a "decorator") we can add to any route
# to make sure the user is logged in.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    """ 
    This is the homepage.
    If the user is logged in, redirect them to the dashboard.
    """
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# --- NEW: Dashboard Route ---
@app.route('/dashboard')
@login_required  # <-- This secures the route
def dashboard():
    """
    This is the user's main dashboard.
    It shows a list of their submitted complaints.
    """
    # Find the user's complaints from the database
    # This uses the 'complaints' relationship we defined in models.py
    user = User.query.get(session['user_id'])
    user_complaints = user.complaints
    
    return render_template('dashboard.html', complaints=user_complaints)

# --- NEW: Submit Complaint Route ---
@app.route('/submit_complaint', methods=['GET', 'POST'])
@login_required # <-- This secures the route
def submit_complaint():
    """
    Shows the complaint form (GET) and handles the submission (POST).
    """
    if request.method == 'POST':
        # Get data from the form
        location = request.form.get('location')
        description = request.form.get('description')

        # Create a new Complaint object
        new_complaint = Complaint(
            location=location,
            description=description,
            user_id=session['user_id'] # Assign it to the logged-in user
            # Status defaults to 'Pending'
        )

        try:
            db.session.add(new_complaint)
            db.session.commit()
            flash('Complaint submitted successfully!', 'success')
            return redirect(url_for('dashboard')) # Go back to dashboard
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            return redirect(url_for('submit_complaint'))

    # If it's a GET request, just show the form page
    return render_template('submit_complaint.html')


# --- Authentication Routes (No Changes) ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        password = request.form.get('password')

        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            phone=phone,
            address=address,
            password=hashed_password
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login')) 
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            session['user_name'] = user.name
            flash(f'Welcome back, {user.name}!', 'success')
            # --- UPDATED: Redirect to dashboard after login ---
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- Main Run ---
if __name__ == '__main__':
    app.run(debug=True)