from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps 
from models import db, User, Complaint 
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = 'your-very-secret-key-change-this' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/locality_issue_hub'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Database ---
db.init_app(app)

# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- NEW: Admin Required Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        
        # Get user's role from the database
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard')) # Redirect non-admins
        
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return render_template('index.html')

# --- User Dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    # --- NEW: Redirect admin users away from user dashboard ---
    if user.role == 'admin':
        flash('Admins are redirected to the admin dashboard.', 'info')
        return redirect(url_for('admin_dashboard'))
        
    user_complaints = user.complaints
    return render_template('dashboard.html', complaints=user_complaints)

@app.route('/submit_complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    if request.method == 'POST':
        location = request.form.get('location')
        description = request.form.get('description')
        new_complaint = Complaint(
            location=location,
            description=description,
            user_id=session['user_id']
        )
        try:
            db.session.add(new_complaint)
            db.session.commit()
            flash('Complaint submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
            return redirect(url_for('submit_complaint'))
    return render_template('submit_complaint.html')

# --- NEW: Admin Dashboard Route ---
@app.route('/admin')
@admin_required  # <-- Secures this route!
def admin_dashboard():
    """
    Shows all complaints from all users.
    We join with the User model to also get the submitter's name.
    """
    all_complaints = db.session.query(Complaint, User).join(User, Complaint.user_id == User.user_id).order_by(Complaint.date_submitted.desc()).all()
    
    # all_complaints is now a list of tuples: [(Complaint_Object, User_Object), ...]
    
    return render_template('admin_dashboard.html', complaints_with_users=all_complaints)

# --- NEW: Admin Update Status Route ---
@app.route('/admin/update_status/<int:complaint_id>', methods=['POST'])
@admin_required
def update_complaint_status(complaint_id):
    """
    Handles the form POST from the admin dashboard to update a status.
    """
    complaint = Complaint.query.get_or_404(complaint_id)
    new_status = request.form.get('status')

    if new_status not in ['Pending', 'In-Progress', 'Resolved']:
        flash('Invalid status selected.', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        complaint.status = new_status
        db.session.commit()
        flash(f'Complaint #{complaint_id} status updated to "{new_status}".', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')
    
    return redirect(url_for('admin_dashboard'))


# --- Authentication Routes (Login route is slightly modified) ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    # ... (No changes here, code is identical) ...
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
            session['user_role'] = user.role
            
            flash(f'Welcome back, {user.name}!', 'success')
            
            # --- MODIFIED: Redirect based on role ---
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
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