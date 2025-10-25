from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize the db object
db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    address = db.Column(db.Text, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='resident') 
    date_registered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # --- NEW RELATIONSHIP ---
    # This links the User to their Complaints.
    # 'complaints' is a 'virtual' field to easily access all complaints for a user.
    complaints = db.relationship('Complaint', backref='submitter', lazy=True)

    def __repr__(self):
        return f'<User {self.name} ({self.email})>'

# --- NEW COMPLAINT MODEL ---
class Complaint(db.Model):
    __tablename__ = 'complaint'
    
    complaint_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    
    # We'll use a string for status: 'Pending', 'In-Progress', 'Resolved'
    status = db.Column(db.String(50), nullable=False, default='Pending')
    
    date_submitted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # --- NEW FOREIGN KEY ---
    # This is the 'link' to the User table.
    # It says this column must match a 'user_id' from the 'user' table.
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)

    def __repr__(self):
        return f'<Complaint {self.complaint_id} ({self.status})>'