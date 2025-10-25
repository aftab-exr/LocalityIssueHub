# Imports from Flask
from flask import Flask, render_template, request, redirect, url_for, flash

# Imports for database
from flask_sqlalchemy import SQLAlchemy
from models import db, User  # <-- Import db and User from models.py

# Imports for password hashing
from werkzeug.security import generate_password_hash

# Create an instance of the Flask class
app = Flask(__name__)

# --- Configuration ---

# We need a SECRET_KEY for 'flash' messages to work
app.config['SECRET_KEY'] = 'your-very-secret-key-change-this'

# Database Connection URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/locality_issue_hub'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Database ---
# Connect our 'db' object from models.py to our Flask app
db.init_app(app)

# --- Routes ---

@app.route('/')
def index():
    """
    This is the homepage.
    """
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    This route handles user registration.
    GET: Shows the registration form.
    POST: Processes the form data and creates a new user.
    """
    if request.method == 'POST':
        # --- 1. Get data from the form ---
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        password = request.form.get('password')

        # --- 2. Check if user already exists ---
        # This relates to "Email Validation: check for duplicates" [cite: 326]
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        # --- 3. Secure the password ---
        # We use generate_password_hash for security
        hashed_password = generate_password_hash(password)

        # --- 4. Create new User object ---
        new_user = User(
            name=name,
            email=email,
            phone=phone,
            address=address,
            password=hashed_password
            # Role defaults to 'resident' as defined in the model
        )

        # --- 5. Add to database and save ---
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Send a success message
            flash('Registration successful! Please log in.', 'success')
            
            # Redirect to the login page (which we will build next)
            # For now, we'll redirect to the homepage
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            return redirect(url_for('register'))

    # If it's a GET request, just show the registration page
    return render_template('register.html')


# This is the code that runs the application
if __name__ == '__main__':
    app.run(debug=True)