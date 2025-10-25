from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy  # <-- Import SQLAlchemy
import pymysql # We still need this for the driver

# Create an instance of the Flask class
app = Flask(__name__)

# --- Database Configuration (The NEW SQLAlchemy Way) ---

# We define the database connection as a single string (URI)
# Format: "mysql+DRIVER://USERNAME:PASSWORD@HOST/DATABASE_NAME"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/locality_issue_hub'

# This line silences a warning and is good practice
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and bind it to our Flask app
# This 'db' object is now our main database connection
db = SQLAlchemy(app)

# --- (The old 'mysql = MySQL(app)' is no longer needed) ---


# --- Routes ---
@app.route('/')
def index():
    """
    This is the homepage.
    It will render our HTML template.
    """
    # Let's add a simple test to prove the database connection works
    try:
        # 'db.session.execute' is how we run a raw SQL query
        db.session.execute('SELECT 1')
        print("--- Database connection successful! ---")
    except Exception as e:
        print(f"--- Database connection FAILED: {e} ---")

    # This line finds and shows your 'index.html' file
    return render_template('index.html')


# This is the code that runs the application
if __name__ == '__main__':
    app.run(debug=True)