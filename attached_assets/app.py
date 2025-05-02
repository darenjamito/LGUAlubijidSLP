from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from datetime import datetime
from werkzeug.utils import secure_filename
import logging
import uuid

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "lgu_alubijid_secret_key")

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'file_management.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Import db and models
from models import db, User, Category, File, user_roles

# Initialize database with app
db.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def get_file_extension(filename):
    return filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv', 'ppt', 'pptx', 'jpg', 'jpeg', 'png'}
    return '.' in filename and get_file_extension(filename) in ALLOWED_EXTENSIONS

def get_unique_filename(filename):
    ext = get_file_extension(filename)
    new_filename = f"{uuid.uuid4().hex}.{ext}"
    return new_filename

# Routes
@app.route("/", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter((User.username == username) | (User.email == username)).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Form validation
        if not all([first_name, last_name, username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
            
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('register.html')
            
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name,
            role=user_roles['USER'],
            status='active'
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    date_filter = request.args.get('date', '')
    sort_by = request.args.get('sort', 'date_desc')
    
    # Base query - filter to show only user's files unless admin
    if current_user.role == user_roles['ADMIN']:
        query = File.query
    else:
        query = File.query.filter_by(user_id=current_user.id)
    
    # Apply search filter
    if search_query:
        query = query.filter(File.filename.contains(search_query) | 
                             File.description.contains(search_query))
    
    # Apply category filter
    if category_filter and category_filter != 'all':
        query = query.filter(File.category_id == category_filter)
    
    # Apply date filter
    if date_filter:
        if date_filter == 'today':
            query = query.filter(db.func.date(File.upload_date) == db.func.date(db.func.now()))
        elif date_filter == 'this_week':
            query = query.filter(db.func.date(File.upload_date) >= db.func.date_sub(db.func.now(), 7))
        elif date_filter == 'this_month':
            query = query.filter(db.func.month(File.upload_date) == db.func.month(db.func.now()))
        elif date_filter == 'this_year':
            query = query.filter(db.func.year(File.upload_date) == db.func.year(db.func.now()))
    
    # Apply sorting
    if sort_by == 'date_asc':
        query = query.order_by(File.upload_date.asc())
    elif sort_by == 'date_desc':
        query = query.order_by(File.upload_date.desc())
    elif sort_by == 'name_asc':
        query = query.order_by(File.filename.asc())
    elif sort_by == 'name_desc':
        query = query.order_by(File.filename.desc())
    elif sort_by == 'size_asc':
        query = query.order_by(File.file_size.asc())
    elif sort_by == 'size_desc':
        query = query.order_by(File.file_size.desc())
    
    # Paginate results
    files_pagination = query.paginate(page=page, per_page=per_page)
    files = files_pagination.items
    
    # Get categories for filter dropdown
    categories = Category.query.all()
    
    return render_template('dashboard.html', 
                           files=files, 
                           pagination=files_pagination,
                           categories=categories,
                           current_category=category_filter,
                           current_search=search_query,
                           current_date=date_filter,
                           current_sort=sort_by)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))
        
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('dashboard'))
        
    if not allowed_file(file.filename):
        flash('File type not allowed', 'error')
        return redirect(url_for('dashboard'))
    
    filename = secure_filename(file.filename)
    unique_filename = get_unique_filename(filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # Get form data
    title = request.form.get('title', filename)
    description = request.form.get('description', '')
    category_id = request.form.get('category_id')
    
    # Save file
    file.save(file_path)
    
    # Create file record in database
    new_file = File(
        filename=title,
        original_filename=filename,
        description=description,
        file_type=get_file_extension(filename),
        file_size=os.path.getsize(file_path),
        storage_path=unique_filename,
        user_id=current_user.id,
        category_id=category_id if category_id else None,
        status='active'
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    flash('File uploaded successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user has permission to download the file
    if file.user_id != current_user.id and current_user.role != user_roles['ADMIN']:
        flash('You do not have permission to download this file', 'error')
        return redirect(url_for('dashboard'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.storage_path)
    
    if not os.path.exists(file_path):
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    
    return send_file(file_path, 
                     as_attachment=True, 
                     download_name=file.original_filename)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user has permission to delete the file
    if file.user_id != current_user.id and current_user.role != user_roles['ADMIN']:
        flash('You do not have permission to delete this file', 'error')
        return redirect(url_for('dashboard'))
    
    # Delete the file from the filesystem
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.storage_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Delete the file record from the database
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user has permission to edit the file
    if file.user_id != current_user.id and current_user.role != user_roles['ADMIN']:
        flash('You do not have permission to edit this file', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Update file details
        file.filename = request.form.get('title')
        file.description = request.form.get('description')
        file.category_id = request.form.get('category_id') if request.form.get('category_id') else None
        
        db.session.commit()
        
        flash('File updated successfully', 'success')
        return redirect(url_for('dashboard'))
    
    # Get categories for the dropdown
    categories = Category.query.all()
    
    return render_template('edit_file.html', file=file, categories=categories)

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        # Update account details
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Check if username or email already exists (excluding current user)
        if username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists', 'error')
                return render_template('account.html')
        
        if email != current_user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already exists', 'error')
                return render_template('account.html')
        
        # Update user details
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.username = username
        current_user.email = email
        
        # Update password if provided
        if new_password:
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('account.html')
            
            current_user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        
        flash('Account updated successfully', 'success')
        return redirect(url_for('account'))
        
    return render_template('account.html')

@app.route('/admin/categories', methods=['GET', 'POST'])
@login_required
def admin_categories():
    # Check if user is an admin
    if current_user.role != user_roles['ADMIN']:
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            # Add new category
            name = request.form.get('name')
            description = request.form.get('description', '')
            
            if not name:
                flash('Category name is required', 'error')
                return redirect(url_for('admin_categories'))
            
            # Check if category already exists
            existing_category = Category.query.filter_by(name=name).first()
            if existing_category:
                flash('Category already exists', 'error')
                return redirect(url_for('admin_categories'))
            
            # Create new category
            new_category = Category(name=name, description=description)
            db.session.add(new_category)
            db.session.commit()
            
            flash('Category added successfully', 'success')
            return redirect(url_for('admin_categories'))
            
        elif action == 'edit':
            # Edit existing category
            category_id = request.form.get('category_id')
            name = request.form.get('name')
            description = request.form.get('description', '')
            
            if not category_id or not name:
                flash('Category ID and name are required', 'error')
                return redirect(url_for('admin_categories'))
            
            # Get category
            category = Category.query.get_or_404(category_id)
            
            # Check if new name already exists (excluding current category)
            if name != category.name:
                existing_category = Category.query.filter_by(name=name).first()
                if existing_category:
                    flash('Category name already exists', 'error')
                    return redirect(url_for('admin_categories'))
            
            # Update category
            category.name = name
            category.description = description
            db.session.commit()
            
            flash('Category updated successfully', 'success')
            return redirect(url_for('admin_categories'))
            
        elif action == 'delete':
            # Delete category
            category_id = request.form.get('category_id')
            
            if not category_id:
                flash('Category ID is required', 'error')
                return redirect(url_for('admin_categories'))
            
            # Get category
            category = Category.query.get_or_404(category_id)
            
            # Check if category has files associated with it
            files = File.query.filter_by(category_id=category.id).first()
            if files:
                flash('Cannot delete category with associated files', 'error')
                return redirect(url_for('admin_categories'))
            
            # Delete category
            db.session.delete(category)
            db.session.commit()
            
            flash('Category deleted successfully', 'success')
            return redirect(url_for('admin_categories'))
    
    # Get all categories
    categories = Category.query.all()
    
    return render_template('admin_categories.html', categories=categories)

# Function to create initial database and admin user
def create_tables_and_admin():
    """
    Function to initialize database tables and create admin user
    This is called from main.py during application startup
    """
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@lgu-alubijid.gov.ph',
                password_hash=generate_password_hash('admin123'),
                first_name='Admin',
                last_name='User',
                role=user_roles['ADMIN'],
                status='active'
            )
            db.session.add(admin)
            
            # Create default categories
            categories = [
                Category(name='Administrative Documents', description='Internal office communications and general operations'),
                Category(name='Personnel Records', description='HR and employee-specific documentation'),
                Category(name='Finance Records', description='Budget, accounting, and fund tracking'),
                Category(name='Project & Program Files', description='Implementation of local government programs and services'),
                Category(name='Legal & Compliance', description='Regulatory, legal, and audit-related documents'),
                Category(name='Barangay Communications', description='Correspondence and reports from barangays under the LGU'),
                Category(name='Public Services', description='Delivery of community services to residents'),
                Category(name='Planning & Development', description='Strategic, demographic, and land-use planning'),
                Category(name='Citizen Records', description='Files directly involving individuals or groups from the public'),
                Category(name='Environmental Documents', description='Files related to ecological compliance and initiatives'),
                Category(name='Others', description='Other documents')
            ]
            
            for category in categories:
                db.session.add(category)
                
            db.session.commit()
            print("Default admin user and categories created")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
