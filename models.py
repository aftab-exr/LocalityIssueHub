from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# We are getting the 'db' object from app.py
# But to avoid circular imports, we initialize it here
# and will connect it to the app in app.py
db = SQLAlchemy()

class User(db.Model):
    # This tells SQLAlchemy what the table name should be
    __tablename__ = 'user'

    # These are the columns, based on your ERD [cite: 210]
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    address = db.Column(db.Text, nullable=True)

    # We will store the *hash* of the password, not the password itself
    password = db.Column(db.String(255), nullable=False)

    # 'resident' or 'admin' or 'authority' [cite: 234, 259]
    role = db.Column(db.String(20), nullable=False, default='resident') 

    date_registered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.name} ({self.email})>'