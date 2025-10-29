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

    # Relationships
    complaints = db.relationship('Complaint', backref='submitter', lazy=True)

    # --- NEW RELATIONSHIPS ---
    posts = db.relationship('ForumPost', backref='author', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('ForumComment', backref='author', lazy=True, cascade="all, delete-orphan")

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
# --- NEW: Local Authority Model ---
class LocalAuthority(db.Model):
    __tablename__ = 'local_authority'

    local_au_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    dept_name = db.Column(db.String(100), nullable=False)
    contact_name = db.Column(db.String(100), nullable=True) # e.g., "Main Office"
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<LocalAuthority {self.dept_name}>'
# --- NEW: Forum Post Model ---

class ForumPost(db.Model):
    __tablename__ = 'forum_post'
    post_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Foreign Key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)

    # Relationship to Comments
    # 'cascade' means if a post is deleted, all its comments are deleted too.
    comments = db.relationship('ForumComment', backref='post', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<ForumPost {self.title}>'

class ForumComment(db.Model):
    __tablename__ = 'forum_comment'
    comment_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Foreign Key to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    # Foreign Key to Post
    post_id = db.Column(db.Integer, db.ForeignKey('forum_post.post_id'), nullable=False)

    def __repr__(self):
        return f'<ForumComment {self.comment_id}>'