from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps 
from models import db, User, Complaint, LocalAuthority
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

# --- Admin Dashboard Route ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    all_complaints = db.session.query(Complaint, User).join(User, Complaint.user_id == User.user_id).order_by(Complaint.date_submitted.desc()).all()
    return render_template('admin_dashboard.html', complaints_with_users=all_complaints)

# --- Admin Update Status Route ---
@app.route('/admin/update_status/<int:complaint_id>', methods=['POST'])
@admin_required
def update_complaint_status(complaint_id):
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


# --- Admin Reports Route (UPDATED) ---
@app.route('/admin/reports')
@admin_required
def admin_reports():
    """
    Displays the report generation page.
    """

    # --- 1. Complaint Status Report (Same as before) ---
    status_counts = db.session.query(
        Complaint.status, 
        db.func.count(Complaint.status)
    ).group_by(Complaint.status).all()

    report_data = {
        'pending': 0,
        'in_progress': 0,
        'resolved': 0
    }

    for status, count in status_counts:
        if status == 'Pending':
            report_data['pending'] = count
        elif status == 'In-Progress':
            report_data['in_progress'] = count
        elif status == 'Resolved':
            report_data['resolved'] = count

    # --- 2. NEW: User Activity Report ---
    # This query joins User and Complaint, groups by User,
    # and counts how many complaints each user has.
    user_activity_data = db.session.query(
        User.user_id,
        User.name,
        User.email,
        User.role,
        db.func.count(Complaint.complaint_id).label('complaint_count')
    ).outerjoin(Complaint, User.user_id == Complaint.user_id) \
     .group_by(User.user_id) \
     .order_by(db.func.count(Complaint.complaint_id).desc()) \
     .all()

    # Pass BOTH report_data AND user_activity_data to the template
    return render_template(
        'admin_reports.html', 
        report_data=report_data, 
        user_activity_data=user_activity_data
    )

# --- NEW: Admin Directory Management ---
@app.route('/admin/directory', methods=['GET', 'POST'])
@admin_required
def admin_directory():
    """
    Admin page to add and view directory contacts.
    """
    if request.method == 'POST':
        # Handle the form submission
        new_contact = LocalAuthority(
            dept_name=request.form.get('dept_name'),
            contact_name=request.form.get('contact_name'),
            phone=request.form.get('phone'),
            email=request.form.get('email'),
            address=request.form.get('address')
        )
        try:
            db.session.add(new_contact)
            db.session.commit()
            flash('New contact added to directory!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

        return redirect(url_for('admin_directory'))

    # For a GET request, show the page with all contacts
    all_contacts = LocalAuthority.query.order_by(LocalAuthority.dept_name).all()
    return render_template('admin_directory.html', contacts=all_contacts)

# --- NEW: Delete Directory Contact ---
@app.route('/admin/directory/delete/<int:contact_id>')
@admin_required
def delete_directory_contact(contact_id):
    """
    Deletes a contact from the directory.
    """
    contact = LocalAuthority.query.get_or_404(contact_id)
    try:
        db.session.delete(contact)
        db.session.commit()
        flash('Contact deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')

    return redirect(url_for('admin_directory'))

# --- NEW: Public Directory Page ---
@app.route('/directory')
@login_required
def directory():
    """
    Displays the public contact directory for all logged-in users.
    """
    # Fetch all contacts from the database
    all_contacts = LocalAuthority.query.order_by(LocalAuthority.dept_name).all()

    # Render the new template, passing in the list of contacts
    return render_template('directory.html', contacts=all_contacts)


# --- Authentication Routes ---

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
            session['user_role'] = user.role
            
            flash(f'Welcome back, {user.name}!', 'success')
            
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
    session.pop('user_role', None) # <-- THIS IS THE FIX
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- Main Run ---
if __name__ == '__main__':
    app.run(debug=True)