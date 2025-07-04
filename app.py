# app.py - Main Flask Application (Monolithic)
import os
from datetime import datetime
from flask import Flask, render_template_string, redirect, url_for, flash, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DecimalField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key_for_md_creations_app'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/product_images'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to login if not authenticated
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database for Flask-Login."""
    return User.query.get(int(user_id))

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='customer', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', Admin: {self.is_admin})"

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False) # e.g., 'Rings', 'Necklaces', 'Earrings'
    material = db.Column(db.String(50), nullable=False) # e.g., 'Gold', 'Silver', 'Diamond'
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(100), nullable=True) # Stores the filename of the image
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    orders = db.relationship('OrderItem', backref='product', lazy=True)

    def __repr__(self):
        return f"Product('{self.name}', '{self.category}', '{self.price}')"

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_price = db.Column(db.Float, nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_address = db.Column(db.String(200), nullable=False)
    customer_contact = db.Column(db.String(20), nullable=False) # Phone number or email
    status = db.Column(db.String(20), nullable=False, default='Pending') # e.g., 'Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'
    items = db.relationship('OrderItem', backref='order', lazy=True)

    def __repr__(self):
        return f"Order('{self.id}', User: {self.user_id}, Total: {self.total_price}, Status: {self.status})"

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_at_order = db.Column(db.Float, nullable=False) # Store price at the time of order

    def __repr__(self):
        return f"OrderItem(Order: {self.order_id}, Product: {self.product_id}, Qty: {self.quantity})"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Null for admin messages
    message_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"Message(From: {self.sender_id}, To: {self.receiver_id}, Time: {self.timestamp})"

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    category = SelectField('Category', choices=[('Ring', 'Rings'), ('Necklace', 'Necklaces'), ('Earring', 'Earrings'), ('Bracelet', 'Bracelets'), ('Pendant', 'Pendants')], validators=[DataRequired()])
    material = StringField('Material', validators=[DataRequired(), Length(max=50)])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Add Product')

class OrderForm(FlaskForm):
    customer_name = StringField('Your Name', validators=[DataRequired(), Length(max=100)])
    customer_address = TextAreaField('Delivery Address', validators=[DataRequired(), Length(max=200)])
    customer_contact = StringField('Contact Number/Email', validators=[DataRequired(), Length(max=20)])
    quantity = SelectField('Quantity', choices=[(str(i), str(i)) for i in range(1, 6)], validators=[DataRequired()])
    submit = SubmitField('Place Order')

class MessageForm(FlaskForm):
    message_text = TextAreaField('Your Message', validators=[DataRequired(), Length(min=1, max=500)])
    submit = SubmitField('Send Message')

# --- Helper Functions ---
def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(f):
    """Decorator to restrict access to admin users only."""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- HTML Templates (Embedded as strings) ---

# Base Layout (Used by all pages)
BASE_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MD Creations - {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f8f8f8;
            color: #333;
        }
        .flash-message {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1000;
            padding: 0.75rem 1.25rem;
            border-radius: 0.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            font-weight: 500;
            animation: fadeOut 5s forwards;
        }
        .flash-message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .flash-message.danger {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .flash-message.info {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        .flash-message.warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }
        @keyframes fadeOut {
            0% { opacity: 1; transform: translateY(0); }
            80% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(-20px); display: none; }
        }
        .form-input {
            @apply w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-pink-500;
        }
        .form-label {
            @apply block text-gray-700 text-sm font-bold mb-2;
        }
        .btn-primary {
            @apply bg-pink-600 hover:bg-pink-700 text-white font-bold py-2 px-4 rounded-md shadow-md transition duration-300;
        }
        .btn-secondary {
            @apply bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded-md shadow-sm transition duration-300;
        }
        .btn-danger {
            @apply bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-md shadow-md transition duration-300;
        }
        .card {
            @apply bg-white p-6 rounded-lg shadow-lg;
        }
        .product-card {
            @apply bg-white rounded-lg shadow-md overflow-hidden transform transition duration-300 hover:scale-105 hover:shadow-xl;
        }
        .product-card img {
            @apply w-full h-48 object-cover;
        }
        .product-card-body {
            @apply p-4;
        }
        .product-card-title {
            @apply text-lg font-semibold text-gray-800 mb-1;
        }
        .product-card-price {
            @apply text-xl font-bold text-pink-600;
        }
        .product-card-category {
            @apply text-sm text-gray-500;
        }
        .product-detail-image-container {
            position: relative;
            cursor: zoom-in;
        }
        .product-detail-image-container img {
            width: 100%;
            height: auto;
            border-radius: 0.75rem;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .modal {
            display: none; /* Hidden by default */
            position: fixed; /* Stay in place */
            z-index: 1000; /* Sit on top */
            left: 0;
            top: 0;
            width: 100%; /* Full width */
            height: 100%; /* Full height */
            overflow: auto; /* Enable scroll if needed */
            background-color: rgba(0,0,0,0.8); /* Black w/ opacity */
            justify-content: center;
            align-items: center;
        }
        .modal-content {
            margin: auto;
            display: block;
            max-width: 90%;
            max-height: 90%;
            border-radius: 0.75rem;
        }
        .modal-close {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            transition: 0.3s;
            cursor: pointer;
        }
        .modal-close:hover,
        .modal-close:focus {
            color: #bbb;
            text-decoration: none;
            cursor: pointer;
        }
        .chat-container {
            display: flex;
            flex-direction: column;
            height: 500px; /* Fixed height for chat area */
            border: 1px solid #e2e8f0;
            border-radius: 0.5rem;
            overflow: hidden;
        }
        .chat-messages {
            flex-grow: 1;
            overflow-y: auto;
            padding: 1rem;
            background-color: #f9fafb;
        }
        .chat-message {
            margin-bottom: 0.75rem;
            display: flex;
        }
        .chat-message.sent {
            justify-content: flex-end;
        }
        .chat-message.received {
            justify-content: flex-start;
        }
        .chat-bubble {
            max-width: 70%;
            padding: 0.75rem 1rem;
            border-radius: 1.25rem;
            line-height: 1.4;
        }
        .chat-message.sent .chat-bubble {
            background-color: #dbf0ff; /* Light blue */
            color: #1f2937;
            border-bottom-right-radius: 0.25rem;
        }
        .chat-message.received .chat-bubble {
            background-color: #f0f0f0; /* Light gray */
            color: #1f2937;
            border-bottom-left-radius: 0.25rem;
        }
        .chat-timestamp {
            font-size: 0.75rem;
            color: #6b7280;
            margin-top: 0.25rem;
            text-align: right;
        }
        .chat-message.received .chat-timestamp {
            text-align: left;
        }
        .chat-input-area {
            padding: 1rem;
            border-top: 1px solid #e2e8f0;
            background-color: #fff;
        }
        .admin-sidebar {
            width: 250px;
            background-color: #1f2937; /* Dark gray */
            color: #e5e7eb;
            padding: 1.5rem;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .admin-sidebar a {
            display: block;
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 0.5rem;
            color: #e5e7eb;
            transition: background-color 0.2s ease;
        }
        .admin-sidebar a:hover {
            background-color: #374151; /* Slightly lighter gray */
        }
        .admin-sidebar a.active {
            background-color: #4b5563; /* Even lighter gray for active */
            font-weight: 600;
        }
        .admin-content {
            flex-grow: 1;
            padding: 1.5rem;
            background-color: #fff;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .admin-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .admin-table th, .admin-table td {
            border: 1px solid #e2e8f0;
            padding: 0.75rem;
            text-align: left;
        }
        .admin-table th {
            background-color: #f3f4f6;
            font-weight: 600;
            color: #374151;
        }
        .admin-table tr:nth-child(even) {
            background-color: #f9fafb;
        }
        .admin-table tr:hover {
            background-color: #edf2f7;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <header class="bg-white shadow-sm py-4">
        <nav class="container mx-auto px-4 flex justify-between items-center">
            <a href="{{ url_for('home') }}" class="text-2xl font-bold text-pink-600">MD Creations</a>
            <div class="flex items-center space-x-6">
                <a href="{{ url_for('home') }}" class="text-gray-700 hover:text-pink-600 transition duration-200">Home</a>
                <a href="{{ url_for('products') }}" class="text-gray-700 hover:text-pink-600 transition duration-200">Products</a>
                {% if current_user.is_authenticated %}
                    <a href="{{ url_for('user_profile') }}" class="text-gray-700 hover:text-pink-600 transition duration-200">Profile</a>
                    <a href="{{ url_for('messages') }}" class="text-gray-700 hover:text-pink-600 transition duration-200">Messages</a>
                    {% if current_user.is_admin %}
                        <a href="{{ url_for('admin_dashboard') }}" class="text-gray-700 hover:text-pink-600 transition duration-200">Admin</a>
                    {% endif %}
                    <a href="{{ url_for('logout') }}" class="btn-secondary">Logout</a>
                {% else %}
                    <a href="{{ url_for('login') }}" class="text-gray-700 hover:text-pink-600 transition duration-200">Login</a>
                    <a href="{{ url_for('signup') }}" class="btn-primary">Sign Up</a>
                {% endif %}
            </div>
        </nav>
    </header>

    <main class="flex-grow container mx-auto px-4 py-8">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash-message {{ category }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {{ content }}
    </main>

    <footer class="bg-gray-800 text-white py-6 mt-auto">
        <div class="container mx-auto px-4 text-center">
            <p>&copy; {{ now.year }} MD Creations. All rights reserved.</p>
            <p class="text-sm mt-2">Premium Jewelry Showcase and Ordering Platform</p>
        </div>
    </footer>

    <script>
        // JavaScript for flash messages (auto-hide)
        document.addEventListener('DOMContentLoaded', function() {
            const flashMessages = document.querySelectorAll('.flash-message');
            flashMessages.forEach(msg => {
                setTimeout(() => {
                    msg.style.opacity = '0';
                    msg.style.transform = 'translateY(-20px)';
                    msg.addEventListener('transitionend', () => msg.remove());
                }, 4000); // Message fades out after 4 seconds
            });
        });

        // SweetAlert for confirmation pop-ups (e.g., delete product)
        function confirmDelete(formId) {
            Swal.fire({
                title: 'Are you sure?',
                text: "You won't be able to revert this!",
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#d33',
                cancelButtonColor: '#3085d6',
                confirmButtonText: 'Yes, delete it!'
            }).then((result) => {
                if (result.isConfirmed) {
                    document.getElementById(formId).submit();
                }
            });
        }
    </script>
</body>
</html>
"""

# Home Page
INDEX_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<section class="text-center py-16 bg-gradient-to-r from-pink-50 to-pink-100 rounded-xl shadow-lg">
    <h1 class="text-5xl font-extrabold text-pink-700 mb-4 animate-fade-in-down">MD Creations</h1>
    <p class="text-xl text-gray-700 mb-8 max-w-2xl mx-auto animate-fade-in-up">
        Your destination for exquisite, handcrafted jewelry. Discover timeless elegance and unparalleled craftsmanship.
    </p>
    <a href="{{ url_for('products') }}" class="btn-primary text-lg px-8 py-3 animate-zoom-in">Explore Our Collection</a>
</section>

<section class="py-12">
    <h2 class="text-3xl font-bold text-gray-800 text-center mb-10">Featured Products</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {% for product in featured_products %}
        <div class="product-card">
            <img src="{{ url_for('static', filename='product_images/' + product.image_filename) if product.image_filename else 'https://placehold.co/400x300/e0e0e0/555555?text=No+Image' }}" alt="{{ product.name }}">
            <div class="product-card-body">
                <h3 class="product-card-title">{{ product.name }}</h3>
                <p class="product-card-category">{{ product.category }} - {{ product.material }}</p>
                <p class="product-card-price">${{ "%.2f"|format(product.price) }}</p>
                <a href="{{ url_for('product_detail', product_id=product.id) }}" class="mt-4 inline-block btn-primary text-sm">View Details</a>
            </div>
        </div>
        {% endfor %}
    </div>
</section>

<section class="py-12 bg-white rounded-xl shadow-lg mt-8">
    <h2 class="text-3xl font-bold text-gray-800 text-center mb-8">About MD Creations</h2>
    <div class="max-w-3xl mx-auto text-gray-700 leading-relaxed text-lg text-center">
        <p class="mb-4">
            At MD Creations, we believe every piece of jewelry tells a story. Founded with a passion for timeless beauty and exceptional quality, we meticulously handcraft each item to bring joy and elegance to your life. From dazzling diamonds to lustrous gold, our collection is designed to celebrate life's precious moments.
        </p>
        <p>
            Our commitment extends beyond exquisite designs; we prioritize ethical sourcing and sustainable practices, ensuring that your beautiful jewelry also carries a beautiful conscience. Explore our unique range and find the perfect piece that resonates with your style.
        </p>
    </div>
</section>
{% endblock %}
"""

# Products Page
PRODUCTS_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<h1 class="text-4xl font-bold text-gray-800 mb-8 text-center">Our Jewelry Collection</h1>

<div class="bg-white p-6 rounded-lg shadow-md mb-8">
    <form method="GET" action="{{ url_for('products') }}" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 items-end">
        <div>
            <label for="category" class="form-label">Category</label>
            <select name="category" id="category" class="form-input">
                <option value="">All Categories</option>
                {% for cat in categories %}
                <option value="{{ cat }}" {% if selected_category == cat %}selected{% endif %}>{{ cat }}</option>
                {% endfor %}
            </select>
        </div>
        <div>
            <label for="material" class="form-label">Material</label>
            <select name="material" id="material" class="form-input">
                <option value="">All Materials</option>
                {% for mat in materials %}
                <option value="{{ mat }}" {% if selected_material == mat %}selected{% endif %}>{{ mat }}</option>
                {% endfor %}
            </select>
        </div>
        <div>
            <label for="min_price" class="form-label">Min Price</label>
            <input type="number" name="min_price" id="min_price" class="form-input" value="{{ min_price if min_price is not none }}">
        </div>
        <div>
            <label for="max_price" class="form-label">Max Price</label>
            <input type="number" name="max_price" id="max_price" class="form-input" value="{{ max_price if max_price is not none }}">
        </div>
        <div class="lg:col-span-2">
            <label for="search" class="form-label">Search</label>
            <input type="text" name="search" id="search" class="form-input" placeholder="Search by name, description, etc." value="{{ search_query if search_query }}">
        </div>
        <div class="md:col-span-2 lg:col-span-2 flex gap-4">
            <button type="submit" class="btn-primary flex-grow">Apply Filters</button>
            <a href="{{ url_for('products') }}" class="btn-secondary flex-grow text-center">Clear Filters</a>
        </div>
    </form>
</div>

{% if products %}
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
    {% for product in products %}
    <div class="product-card">
        <img src="{{ url_for('static', filename='product_images/' + product.image_filename) if product.image_filename else 'https://placehold.co/400x300/e0e0e0/555555?text=No+Image' }}" alt="{{ product.name }}">
        <div class="product-card-body">
            <h3 class="product-card-title">{{ product.name }}</h3>
            <p class="product-card-category">{{ product.category }} - {{ product.material }}</p>
            <p class="product-card-price">${{ "%.2f"|format(product.price) }}</p>
            <a href="{{ url_for('product_detail', product_id=product.id) }}" class="mt-4 inline-block btn-primary text-sm">View Details</a>
        </div>
    </div>
    {% endfor %}
</div>
{% else %}
<p class="text-center text-gray-600 text-xl mt-10">No products found matching your criteria.</p>
{% endif %}
{% endblock %}
"""

# Product Detail Page
PRODUCT_DETAIL_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="bg-white rounded-lg shadow-xl p-8 flex flex-col md:flex-row gap-8">
    <div class="md:w-1/2 product-detail-image-container" id="productImageContainer">
        <img src="{{ url_for('static', filename='product_images/' + product.image_filename) if product.image_filename else 'https://placehold.co/600x450/e0e0e0/555555?text=No+Image' }}" alt="{{ product.name }}" class="rounded-xl shadow-md">
    </div>
    <div class="md:w-1/2">
        <h1 class="text-4xl font-bold text-gray-800 mb-4">{{ product.name }}</h1>
        <p class="text-2xl font-semibold text-pink-600 mb-4">${{ "%.2f"|format(product.price) }}</p>
        <p class="text-gray-600 mb-2"><strong>Category:</strong> {{ product.category }}</p>
        <p class="text-gray-600 mb-4"><strong>Material:</strong> {{ product.material }}</p>
        <p class="text-gray-700 leading-relaxed mb-6">{{ product.description }}</p>

        <h2 class="text-2xl font-semibold text-gray-800 mb-4">Place Your Order</h2>
        <form method="POST" class="space-y-4">
            {{ form.csrf_token }}
            <div>
                <label for="customer_name" class="form-label">{{ form.customer_name.label }}</label>
                {{ form.customer_name(class="form-input", placeholder="Your Full Name") }}
                {% for error in form.customer_name.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="customer_address" class="form-label">{{ form.customer_address.label }}</label>
                {{ form.customer_address(class="form-input", rows="3", placeholder="Your Delivery Address") }}
                {% for error in form.customer_address.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="customer_contact" class="form-label">{{ form.customer_contact.label }}</label>
                {{ form.customer_contact(class="form-input", placeholder="Your Contact Number or Email") }}
                {% for error in form.customer_contact.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="quantity" class="form-label">{{ form.quantity.label }}</label>
                {{ form.quantity(class="form-input") }}
                {% for error in form.quantity.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                {{ form.submit(class="btn-primary w-full") }}
            </div>
        </form>
    </div>
</div>

<!-- The Modal for Image Zoom -->
<div id="imageZoomModal" class="modal">
    <span class="modal-close">&times;</span>
    <img class="modal-content" id="img01">
</div>

<script>
    // Get the modal
    var modal = document.getElementById("imageZoomModal");
    var imgContainer = document.getElementById("productImageContainer");
    var modalImg = document.getElementById("img01");

    imgContainer.onclick = function(){
        modal.style.display = "flex";
        modalImg.src = this.querySelector('img').src;
    }

    // Get the <span> element that closes the modal
    var span = document.getElementsByClassName("modal-close")[0];

    // When the user clicks on <span> (x), close the modal
    span.onclick = function() {
        modal.style.display = "none";
    }

    // Close modal when clicking outside the image
    modal.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }
</script>
{% endblock %}
"""

# Auth Pages
SIGNUP_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex justify-center items-center py-12">
    <div class="card w-full max-w-md">
        <h1 class="text-3xl font-bold text-gray-800 text-center mb-6">Sign Up for MD Creations</h1>
        <form method="POST" class="space-y-4">
            {{ form.csrf_token }}
            <div>
                <label for="username" class="form-label">{{ form.username.label }}</label>
                {{ form.username(class="form-input", placeholder="Choose a username") }}
                {% for error in form.username.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="email" class="form-label">{{ form.email.label }}</label>
                {{ form.email(class="form-input", placeholder="Enter your email") }}
                {% for error in form.email.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="password" class="form-label">{{ form.password.label }}</label>
                {{ form.password(class="form-input", placeholder="Create a password") }}
                {% for error in form.password.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="confirm_password" class="form-label">{{ form.confirm_password.label }}</label>
                {{ form.confirm_password(class="form-input", placeholder="Confirm your password") }}
                {% for error in form.confirm_password.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                {{ form.submit(class="btn-primary w-full") }}
            </div>
        </form>
        <p class="text-center text-gray-600 mt-4">
            Already have an account? <a href="{{ url_for('login') }}" class="text-pink-600 hover:underline">Login here</a>
        </p>
    </div>
</div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex justify-center items-center py-12">
    <div class="card w-full max-w-md">
        <h1 class="text-3xl font-bold text-gray-800 text-center mb-6">Login to MD Creations</h1>
        <form method="POST" class="space-y-4">
            {{ form.csrf_token }}
            <div>
                <label for="email" class="form-label">{{ form.email.label }}</label>
                {{ form.email(class="form-input", placeholder="Enter your email") }}
                {% for error in form.email.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="password" class="form-label">{{ form.password.label }}</label>
                {{ form.password(class="form-input", placeholder="Enter your password") }}
                {% for error in form.password.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                {{ form.submit(class="btn-primary w-full") }}
            </div>
        </form>
        <p class="text-center text-gray-600 mt-4">
            Don't have an account? <a href="{{ url_for('signup') }}" class="text-pink-600 hover:underline">Sign Up here</a>
        </p>
    </div>
</div>
{% endblock %}
"""

# User Profile Page
USER_PROFILE_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="bg-white rounded-lg shadow-xl p-8">
    <h1 class="text-4xl font-bold text-gray-800 mb-6">Welcome, {{ user.username }}!</h1>

    <div class="mb-8">
        <h2 class="text-2xl font-semibold text-gray-800 mb-4">Your Details</h2>
        <p class="text-lg text-gray-700"><strong>Email:</strong> {{ user.email }}</p>
        <p class="text-lg text-gray-700"><strong>Account Type:</strong> {{ 'Admin' if user.is_admin else 'Regular User' }}</p>
    </div>

    <div>
        <h2 class="text-2xl font-semibold text-gray-800 mb-4">Your Past Orders</h2>
        {% if orders %}
        <div class="overflow-x-auto">
            <table class="min-w-full bg-white rounded-lg shadow-md admin-table">
                <thead>
                    <tr>
                        <th class="py-3 px-4">Order ID</th>
                        <th class="py-3 px-4">Date</th>
                        <th class="py-3 px-4">Total Price</th>
                        <th class="py-3 px-4">Status</th>
                        <th class="py-3 px-4">Items</th>
                    </tr>
                </thead>
                <tbody>
                    {% for order in orders %}
                    <tr>
                        <td class="py-3 px-4">{{ order.id }}</td>
                        <td class="py-3 px-4">{{ order.order_date.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td class="py-3 px-4">${{ "%.2f"|format(order.total_price) }}</td>
                        <td class="py-3 px-4">
                            <span class="px-2 py-1 rounded-full text-xs font-semibold
                                {% if order.status == 'Pending' %} bg-yellow-100 text-yellow-800
                                {% elif order.status == 'Processing' %} bg-blue-100 text-blue-800
                                {% elif order.status == 'Shipped' %} bg-indigo-100 text-indigo-800
                                {% elif order.status == 'Delivered' %} bg-green-100 text-green-800
                                {% elif order.status == 'Cancelled' %} bg-red-100 text-red-800
                                {% endif %}">
                                {{ order.status }}
                            </span>
                        </td>
                        <td class="py-3 px-4">
                            <ul class="list-disc pl-5">
                                {% for item in order.items %}
                                    <li>{{ item.quantity }} x {{ item.product.name }} (${{ "%.2f"|format(item.price_at_order) }} each)</li>
                                {% endfor %}
                            </ul>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p class="text-gray-600">You haven't placed any orders yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
"""

# User Messages Page
USER_MESSAGES_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="bg-white rounded-lg shadow-xl p-8">
    <h1 class="text-4xl font-bold text-gray-800 mb-6 text-center">Contact Admin</h1>

    <div class="chat-container">
        <div class="chat-messages" id="chatMessages">
            {% for message in messages %}
                <div class="chat-message {% if message.sender_id == current_user.id %}sent{% else %}received{% endif %}">
                    <div class="flex flex-col">
                        <div class="chat-bubble">
                            {{ message.message_text }}
                        </div>
                        <span class="chat-timestamp">{{ message.timestamp.strftime('%b %d, %H:%M') }}</span>
                    </div>
                </div>
            {% endfor %}
        </div>
        <div class="chat-input-area">
            <form method="POST" class="flex gap-4">
                {{ form.csrf_token }}
                <div class="flex-grow">
                    {{ form.message_text(class="form-input", rows="1", placeholder="Type your message...", oninput="this.style.height = 'auto'; this.style.height = (this.scrollHeight) + 'px';") }}
                    {% for error in form.message_text.errors %}
                        <span class="text-red-500 text-sm">{{ error }}</span>
                    {% endfor %}
                </div>
                <div>
                    {{ form.submit(class="btn-primary") }}
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    // Scroll to the bottom of the chat messages div
    document.addEventListener('DOMContentLoaded', function() {
        var chatMessages = document.getElementById('chatMessages');
        chatMessages.scrollTop = chatMessages.scrollHeight;
    });
</script>
{% endblock %}
"""

# Admin Pages
ADMIN_DASHBOARD_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex flex-col md:flex-row gap-8">
    <div class="admin-sidebar">
        <h2 class="text-2xl font-bold mb-6 text-white">Admin Panel</h2>
        <ul>
            <li><a href="{{ url_for('admin_dashboard') }}" class="active"><i class="fas fa-tachometer-alt mr-2"></i> Dashboard</a></li>
            <li><a href="{{ url_for('admin_products') }}"><i class="fas fa-box-open mr-2"></i> Manage Products</a></li>
            <li><a href="{{ url_for('admin_orders') }}"><i class="fas fa-shopping-cart mr-2"></i> View Orders</a></li>
            <li><a href="{{ url_for('admin_users') }}"><i class="fas fa-users mr-2"></i> View Users</a></li>
            <li><a href="{{ url_for('admin_messages') }}"><i class="fas fa-envelope mr-2"></i> Messages</a></li>
        </ul>
    </div>
    <div class="admin-content">
        <h1 class="text-4xl font-bold text-gray-800 mb-6">Admin Dashboard</h1>

        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div class="card text-center">
                <i class="fas fa-box-open text-pink-600 text-4xl mb-3"></i>
                <h3 class="text-xl font-semibold text-gray-700">Total Products</h3>
                <p class="text-4xl font-bold text-gray-900">{{ total_products }}</p>
            </div>
            <div class="card text-center">
                <i class="fas fa-users text-blue-600 text-4xl mb-3"></i>
                <h3 class="text-xl font-semibold text-gray-700">Total Users</h3>
                <p class="text-4xl font-bold text-gray-900">{{ total_users }}</p>
            </div>
            <div class="card text-center">
                <i class="fas fa-shopping-cart text-green-600 text-4xl mb-3"></i>
                <h3 class="text-xl font-semibold text-gray-700">Total Orders</h3>
                <p class="text-4xl font-bold text-gray-900">{{ total_orders }}</p>
            </div>
            <div class="card text-center">
                <i class="fas fa-hourglass-half text-yellow-600 text-4xl mb-3"></i>
                <h3 class="text-xl font-semibold text-gray-700">Pending Orders</h3>
                <p class="text-4xl font-bold text-gray-900">{{ pending_orders }}</p>
            </div>
        </div>

        {# Optional: Chart.js integration for more detailed stats #}
        {# <div class="card mt-8">
            <h2 class="text-2xl font-semibold text-gray-800 mb-4">Order Status Distribution</h2>
            <canvas id="orderStatusChart"></canvas>
        </div> #}
    </div>
</div>

{#
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Example Chart.js data (you'd fetch this dynamically in a real app)
        const orderStatusData = {
            labels: ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'],
            datasets: [{
                label: 'Number of Orders',
                data: [{{ pending_orders }}, 10, 5, 20, 2], // Replace with actual counts
                backgroundColor: [
                    'rgba(255, 205, 86, 0.6)', // Yellow
                    'rgba(54, 162, 235, 0.6)', // Blue
                    'rgba(75, 192, 192, 0.6)', // Green
                    'rgba(153, 102, 255, 0.6)', // Purple
                    'rgba(255, 99, 132, 0.6)'  // Red
                ],
                borderColor: [
                    'rgba(255, 205, 86, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)',
                    'rgba(255, 99, 132, 1)'
                ],
                borderWidth: 1
            }]
        };

        const config = {
            type: 'doughnut',
            data: orderStatusData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Order Status Distribution'
                    }
                }
            },
        };

        const orderStatusChart = new Chart(
            document.getElementById('orderStatusChart'),
            config
        );
    });
</script>
#}
{% endblock %}
"""

ADMIN_PRODUCTS_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex flex-col md:flex-row gap-8">
    <div class="admin-sidebar">
        <h2 class="text-2xl font-bold mb-6 text-white">Admin Panel</h2>
        <ul>
            <li><a href="{{ url_for('admin_dashboard') }}"><i class="fas fa-tachometer-alt mr-2"></i> Dashboard</a></li>
            <li><a href="{{ url_for('admin_products') }}" class="active"><i class="fas fa-box-open mr-2"></i> Manage Products</a></li>
            <li><a href="{{ url_for('admin_orders') }}"><i class="fas fa-shopping-cart mr-2"></i> View Orders</a></li>
            <li><a href="{{ url_for('admin_users') }}"><i class="fas fa-users mr-2"></i> View Users</a></li>
            <li><a href="{{ url_for('admin_messages') }}"><i class="fas fa-envelope mr-2"></i> Messages</a></li>
        </ul>
    </div>
    <div class="admin-content">
        <h1 class="text-4xl font-bold text-gray-800 mb-6">Manage Products</h1>

        <a href="{{ url_for('add_product') }}" class="btn-primary mb-6 inline-block"><i class="fas fa-plus-circle mr-2"></i> Add New Product</a>

        {% if products %}
        <div class="overflow-x-auto">
            <table class="min-w-full bg-white rounded-lg shadow-md admin-table">
                <thead>
                    <tr>
                        <th class="py-3 px-4">ID</th>
                        <th class="py-3 px-4">Image</th>
                        <th class="py-3 px-4">Name</th>
                        <th class="py-3 px-4">Category</th>
                        <th class="py-3 px-4">Material</th>
                        <th class="py-3 px-4">Price</th>
                        <th class="py-3 px-4">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for product in products %}
                    <tr>
                        <td class="py-3 px-4">{{ product.id }}</td>
                        <td class="py-3 px-4">
                            <img src="{{ url_for('static', filename='product_images/' + product.image_filename) if product.image_filename else 'https://placehold.co/50x50/e0e0e0/555555?text=No' }}" alt="{{ product.name }}" class="w-12 h-12 object-cover rounded-md">
                        </td>
                        <td class="py-3 px-4">{{ product.name }}</td>
                        <td class="py-3 px-4">{{ product.category }}</td>
                        <td class="py-3 px-4">{{ product.material }}</td>
                        <td class="py-3 px-4">${{ "%.2f"|format(product.price) }}</td>
                        <td class="py-3 px-4 flex space-x-2">
                            <a href="{{ url_for('edit_product', product_id=product.id) }}" class="btn-secondary text-sm"><i class="fas fa-edit"></i> Edit</a>
                            <form id="deleteForm{{ product.id }}" action="{{ url_for('delete_product', product_id=product.id) }}" method="POST" class="inline">
                                <button type="button" onclick="confirmDelete('deleteForm{{ product.id }}')" class="btn-danger text-sm"><i class="fas fa-trash-alt"></i> Delete</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p class="text-center text-gray-600 text-xl mt-10">No products added yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
"""

ADD_PRODUCT_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex flex-col md:flex-row gap-8">
    <div class="admin-sidebar">
        <h2 class="text-2xl font-bold mb-6 text-white">Admin Panel</h2>
        <ul>
            <li><a href="{{ url_for('admin_dashboard') }}"><i class="fas fa-tachometer-alt mr-2"></i> Dashboard</a></li>
            <li><a href="{{ url_for('admin_products') }}" class="active"><i class="fas fa-box-open mr-2"></i> Manage Products</a></li>
            <li><a href="{{ url_for('admin_orders') }}"><i class="fas fa-shopping-cart mr-2"></i> View Orders</a></li>
            <li><a href="{{ url_for('admin_users') }}"><i class="fas fa-users mr-2"></i> View Users</a></li>
            <li><a href="{{ url_for('admin_messages') }}"><i class="fas fa-envelope mr-2"></i> Messages</a></li>
        </ul>
    </div>
    <div class="admin-content">
        <h1 class="text-4xl font-bold text-gray-800 mb-6">{{ 'Add New Product' if not product else 'Edit Product: ' + product.name }}</h1>

        <form method="POST" enctype="multipart/form-data" class="space-y-6">
            {{ form.csrf_token }}
            <div>
                <label for="name" class="form-label">{{ form.name.label }}</label>
                {{ form.name(class="form-input", placeholder="Product Name") }}
                {% for error in form.name.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="category" class="form-label">{{ form.category.label }}</label>
                {{ form.category(class="form-input") }}
                {% for error in form.category.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="material" class="form-label">{{ form.material.label }}</label>
                {{ form.material(class="form-input", placeholder="e.g., Gold, Silver, Diamond") }}
                {% for error in form.material.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="price" class="form-label">{{ form.price.label }}</label>
                {{ form.price(class="form-input", placeholder="e.g., 99.99") }}
                {% for error in form.price.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="description" class="form-label">{{ form.description.label }}</label>
                {{ form.description(class="form-input", rows="5", placeholder="Detailed description of the product...") }}
                {% for error in form.description.errors %}
                    <span class="text-red-500 text-sm">{{ error }}</span>
                {% endfor %}
            </div>
            <div>
                <label for="image" class="form-label">Product Image (PNG, JPG, JPEG, GIF)</label>
                <input type="file" name="image" id="image" class="form-input border-none p-0 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-pink-50 file:text-pink-700 hover:file:bg-pink-100">
                {% if product and product.image_filename %}
                    <p class="text-sm text-gray-500 mt-2">Current image: <a href="{{ url_for('static', filename='product_images/' + product.image_filename) }}" target="_blank" class="text-pink-600 hover:underline">{{ product.image_filename }}</a></p>
                    <img src="{{ url_for('static', filename='product_images/' + product.image_filename) }}" alt="Current Product Image" class="w-32 h-32 object-cover rounded-md mt-2">
                {% endif %}
            </div>
            <div>
                {{ form.submit(class="btn-primary") }}
                <a href="{{ url_for('admin_products') }}" class="btn-secondary ml-4">Cancel</a>
            </div>
        </form>
    </div>
</div>
{% endblock %}
"""

ADMIN_ORDERS_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex flex-col md:flex-row gap-8">
    <div class="admin-sidebar">
        <h2 class="text-2xl font-bold mb-6 text-white">Admin Panel</h2>
        <ul>
            <li><a href="{{ url_for('admin_dashboard') }}"><i class="fas fa-tachometer-alt mr-2"></i> Dashboard</a></li>
            <li><a href="{{ url_for('admin_products') }}"><i class="fas fa-box-open mr-2"></i> Manage Products</a></li>
            <li><a href="{{ url_for('admin_orders') }}" class="active"><i class="fas fa-shopping-cart mr-2"></i> View Orders</a></li>
            <li><a href="{{ url_for('admin_users') }}"><i class="fas fa-users mr-2"></i> View Users</a></li>
            <li><a href="{{ url_for('admin_messages') }}"><i class="fas fa-envelope mr-2"></i> Messages</a></li>
        </ul>
    </div>
    <div class="admin-content">
        <h1 class="text-4xl font-bold text-gray-800 mb-6">Manage Orders</h1>

        {% if orders %}
        <div class="overflow-x-auto">
            <table class="min-w-full bg-white rounded-lg shadow-md admin-table">
                <thead>
                    <tr>
                        <th class="py-3 px-4">Order ID</th>
                        <th class="py-3 px-4">Customer</th>
                        <th class="py-3 px-4">Contact</th>
                        <th class="py-3 px-4">Address</th>
                        <th class="py-3 px-4">Date</th>
                        <th class="py-3 px-4">Total</th>
                        <th class="py-3 px-4">Items</th>
                        <th class="py-3 px-4">Status</th>
                        <th class="py-3 px-4">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for order in orders %}
                    <tr>
                        <td class="py-3 px-4">{{ order.id }}</td>
                        <td class="py-3 px-4">{{ order.customer_name }} (User ID: {{ order.user_id }})</td>
                        <td class="py-3 px-4">{{ order.customer_contact }}</td>
                        <td class="py-3 px-4">{{ order.customer_address }}</td>
                        <td class="py-3 px-4">{{ order.order_date.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td class="py-3 px-4">${{ "%.2f"|format(order.total_price) }}</td>
                        <td class="py-3 px-4">
                            <ul class="list-disc pl-5 text-sm">
                                {% for item in order.items %}
                                    <li>{{ item.quantity }} x {{ item.product.name }}</li>
                                {% endfor %}
                            </ul>
                        </td>
                        <td class="py-3 px-4">
                            <span class="px-2 py-1 rounded-full text-xs font-semibold
                                {% if order.status == 'Pending' %} bg-yellow-100 text-yellow-800
                                {% elif order.status == 'Processing' %} bg-blue-100 text-blue-800
                                {% elif order.status == 'Shipped' %} bg-indigo-100 text-indigo-800
                                {% elif order.status == 'Delivered' %} bg-green-100 text-green-800
                                {% elif order.status == 'Cancelled' %} bg-red-100 text-red-800
                                {% endif %}">
                                {{ order.status }}
                            </span>
                        </td>
                        <td class="py-3 px-4">
                            <form action="{{ url_for('update_order_status', order_id=order.id) }}" method="POST" class="flex flex-col space-y-2">
                                <select name="status" class="form-input text-sm py-1">
                                    <option value="Pending" {% if order.status == 'Pending' %}selected{% endif %}>Pending</option>
                                    <option value="Processing" {% if order.status == 'Processing' %}selected{% endif %}>Processing</option>
                                    <option value="Shipped" {% if order.status == 'Shipped' %}selected{% endif %}>Shipped</option>
                                    <option value="Delivered" {% if order.status == 'Delivered' %}selected{% endif %}>Delivered</option>
                                    <option value="Cancelled" {% if order.status == 'Cancelled' %}selected{% endif %}>Cancelled</option>
                                </select>
                                <button type="submit" class="btn-primary text-xs py-1">Update</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p class="text-center text-gray-600 text-xl mt-10">No orders placed yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
"""

ADMIN_USERS_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex flex-col md:flex-row gap-8">
    <div class="admin-sidebar">
        <h2 class="text-2xl font-bold mb-6 text-white">Admin Panel</h2>
        <ul>
            <li><a href="{{ url_for('admin_dashboard') }}"><i class="fas fa-tachometer-alt mr-2"></i> Dashboard</a></li>
            <li><a href="{{ url_for('admin_products') }}"><i class="fas fa-box-open mr-2"></i> Manage Products</a></li>
            <li><a href="{{ url_for('admin_orders') }}"><i class="fas fa-shopping-cart mr-2"></i> View Orders</a></li>
            <li><a href="{{ url_for('admin_users') }}" class="active"><i class="fas fa-users mr-2"></i> View Users</a></li>
            <li><a href="{{ url_for('admin_messages') }}"><i class="fas fa-envelope mr-2"></i> Messages</a></li>
        </ul>
    </div>
    <div class="admin-content">
        <h1 class="text-4xl font-bold text-gray-800 mb-6">Manage Users</h1>

        {% if users %}
        <div class="overflow-x-auto">
            <table class="min-w-full bg-white rounded-lg shadow-md admin-table">
                <thead>
                    <tr>
                        <th class="py-3 px-4">ID</th>
                        <th class="py-3 px-4">Username</th>
                        <th class="py-3 px-4">Email</th>
                        <th class="py-3 px-4">Account Type</th>
                        <th class="py-3 px-4">Registered On</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td class="py-3 px-4">{{ user.id }}</td>
                        <td class="py-3 px-4">{{ user.username }}</td>
                        <td class="py-3 px-4">{{ user.email }}</td>
                        <td class="py-3 px-4">
                            <span class="px-2 py-1 rounded-full text-xs font-semibold
                                {% if user.is_admin %} bg-purple-100 text-purple-800
                                {% else %} bg-gray-100 text-gray-800
                                {% endif %}">
                                {{ 'Admin' if user.is_admin else 'User' }}
                            </span>
                        </td>
                        <td class="py-3 px-4">{{ user.id | get_user_registration_date }}</td> {# Assuming user.id can be used to get creation date, or add a 'date_registered' field to User model #}
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p class="text-center text-gray-600 text-xl mt-10">No users registered yet.</p>
        {% endif %}
    </div>
</div>
{% endblock %}
"""

ADMIN_MESSAGES_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="flex flex-col md:flex-row gap-8">
    <div class="admin-sidebar">
        <h2 class="text-2xl font-bold mb-6 text-white">Admin Panel</h2>
        <ul>
            <li><a href="{{ url_for('admin_dashboard') }}"><i class="fas fa-tachometer-alt mr-2"></i> Dashboard</a></li>
            <li><a href="{{ url_for('admin_products') }}"><i class="fas fa-box-open mr-2"></i> Manage Products</a></li>
            <li><a href="{{ url_for('admin_orders') }}"><i class="fas fa-shopping-cart mr-2"></i> View Orders</a></li>
            <li><a href="{{ url_for('admin_users') }}"><i class="fas fa-users mr-2"></i> View Users</a></li>
            <li><a href="{{ url_for('admin_messages') }}" class="active"><i class="fas fa-envelope mr-2"></i> Messages</a></li>
        </ul>
    </div>
    <div class="admin-content flex flex-col h-[600px]"> {# Fixed height for admin content to make chat scrollable #}
        <h1 class="text-4xl font-bold text-gray-800 mb-6">Admin Messages</h1>

        <div class="flex flex-grow gap-6">
            <div class="w-1/3 bg-gray-50 p-4 rounded-lg shadow-inner overflow-y-auto">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Users with Messages</h3>
                {% if users_with_messages %}
                    <ul class="space-y-2">
                        {% for user_msg in users_with_messages %}
                            <li class="p-3 rounded-md cursor-pointer hover:bg-gray-200 transition duration-200
                                {% if selected_user and selected_user.id == user_msg.id %}bg-pink-100{% endif %}">
                                <a href="{{ url_for('admin_messages', user_id=user_msg.id) }}" class="block text-gray-800 font-medium">
                                    {{ user_msg.username }}
                                    {% set unread_count = user_msg.messages_received|selectattr('is_read', '==', false)|selectattr('sender_id', '==', user_msg.id)|list|length %}
                                    {% if unread_count > 0 %}
                                        <span class="ml-2 px-2 py-0.5 bg-red-500 text-white text-xs rounded-full">{{ unread_count }} new</span>
                                    {% endif %}
                                </a>
                            </li>
                        {% endfor %}
                    </ul>
                {% else %}
                    <p class="text-gray-600 text-sm">No user messages yet.</p>
                {% endif %}
            </div>

            <div class="w-2/3 flex flex-col bg-white rounded-lg shadow-md border border-gray-200">
                {% if selected_user %}
                    <div class="p-4 border-b border-gray-200 bg-gray-50">
                        <h3 class="text-xl font-semibold text-gray-800">Chat with {{ selected_user.username }}</h3>
                    </div>
                    <div class="chat-messages flex-grow overflow-y-auto p-4" id="adminChatMessages">
                        {% for message in messages %}
                            <div class="chat-message {% if message.sender_id == current_user.id %}sent{% else %}received{% endif %}">
                                <div class="flex flex-col">
                                    <div class="chat-bubble">
                                        {{ message.message_text }}
                                    </div>
                                    <span class="chat-timestamp">{{ message.timestamp.strftime('%b %d, %H:%M') }}</span>
                                </div>
                            </div>
                        {% endfor %}
                    </div>
                    <div class="chat-input-area border-t border-gray-200 p-4">
                        <form method="POST" class="flex gap-4">
                            {{ form.csrf_token }}
                            <div class="flex-grow">
                                {{ form.message_text(class="form-input", rows="1", placeholder="Reply to {{ selected_user.username }}...", oninput="this.style.height = 'auto'; this.style.height = (this.scrollHeight) + 'px';") }}
                                {% for error in form.message_text.errors %}
                                    <span class="text-red-500 text-sm">{{ error }}</span>
                                {% endfor %}
                            </div>
                            <div>
                                {{ form.submit(class="btn-primary") }}
                            </div>
                        </form>
                    </div>
                {% else %}
                    <div class="flex-grow flex items-center justify-center text-gray-600 text-lg">
                        Select a user from the left to view their messages.
                    </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>

<script>
    // Scroll to the bottom of the chat messages div
    document.addEventListener('DOMContentLoaded', function() {
        var adminChatMessages = document.getElementById('adminChatMessages');
        if (adminChatMessages) {
            adminChatMessages.scrollTop = adminChatMessages.scrollHeight;
        }
    });
</script>
{% endblock %}
"""

# Error Pages
ERROR_404_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="text-center py-20">
    <h1 class="text-6xl font-bold text-gray-800 mb-4">404</h1>
    <h2 class="text-3xl font-semibold text-gray-700 mb-6">Page Not Found</h2>
    <p class="text-lg text-gray-600 mb-8">The page you are looking for does not exist.</p>
    <a href="{{ url_for('home') }}" class="btn-primary">Go to Home Page</a>
</div>
{% endblock %}
"""

ERROR_500_HTML = """
{% extends "base_layout" %}
{% set now = now %}
{% block content %}
<div class="text-center py-20">
    <h1 class="text-6xl font-bold text-red-600 mb-4">500</h1>
    <h2 class="text-3xl font-semibold text-gray-700 mb-6">Internal Server Error</h2>
    <p class="text-lg text-gray-600 mb-8">Something went wrong on our end. Please try again later.</p>
    <a href="{{ url_for('home') }}" class="btn-primary">Go to Home Page</a>
</div>
{% endblock %}
"""

# --- Routes ---

# --- User Routes ---
@app.route('/')
@app.route('/home')
def home():
    """Home page - displays company info and product highlights."""
    featured_products = Product.query.order_by(Product.date_added.desc()).limit(3).all()
    return render_template_string(BASE_LAYOUT + INDEX_HTML, title='Home', featured_products=featured_products, now=datetime.utcnow())

@app.route('/products')
def products():
    """Displays all jewelry products with filtering options."""
    category = request.args.get('category')
    material = request.args.get('material')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    search_query = request.args.get('search')

    products_query = Product.query

    if category:
        products_query = products_query.filter_by(category=category)
    if material:
        products_query = products_query.filter_by(material=material)
    if min_price is not None:
        products_query = products_query.filter(Product.price >= min_price)
    if max_price is not None:
        products_query = products_query.filter(Product.price <= max_price)
    if search_query:
        products_query = products_query.filter(Product.name.ilike(f'%{search_query}%') |
                                               Product.description.ilike(f'%{search_query}%') |
                                               Product.category.ilike(f'%{search_query}%') |
                                               Product.material.ilike(f'%{search_query}%'))

    all_products = products_query.order_by(Product.name).all()

    categories = sorted(list(set(p.category for p in Product.query.with_entities(Product.category).distinct())))
    materials = sorted(list(set(p.material for p in Product.query.with_entities(Product.material).distinct())))

    return render_template_string(BASE_LAYOUT + PRODUCTS_HTML, title='All Products', products=all_products,
                           categories=categories, materials=materials,
                           selected_category=category, selected_material=material,
                           min_price=min_price, max_price=max_price, search_query=search_query, now=datetime.utcnow())

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    """Displays detailed product information and allows placing an order."""
    product = Product.query.get_or_404(product_id)
    form = OrderForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Please log in to place an order.', 'info')
            return redirect(url_for('login', next=request.url))

        quantity = int(form.quantity.data)
        total_price = product.price * quantity

        order = Order(
            user_id=current_user.id,
            total_price=total_price,
            customer_name=form.customer_name.data,
            customer_address=form.customer_address.data,
            customer_contact=form.customer_contact.data,
            status='Pending'
        )
        db.session.add(order)
        db.session.flush()

        order_item = OrderItem(
            order_id=order.id,
            product_id=product.id,
            quantity=quantity,
            price_at_order=product.price
        )
        db.session.add(order_item)
        db.session.commit()

        flash(f'Your order for {quantity} x {product.name} has been placed successfully!', 'success')
        return redirect(url_for('user_profile'))
    return render_template_string(BASE_LAYOUT + PRODUCT_DETAIL_HTML, title=product.name, product=product, form=form, now=datetime.utcnow())

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration page."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template_string(BASE_LAYOUT + SIGNUP_HTML, title='Sign Up', form=form, now=datetime.utcnow())

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template_string(BASE_LAYOUT + LOGIN_HTML, title='Login', form=form, now=datetime.utcnow())

@app.route('/logout')
@login_required
def logout():
    """Logs out the current user."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def user_profile():
    """User profile page - view past orders and personal details."""
    user_orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.order_date.desc()).all()
    # Add a custom filter to Jinja2 for getting user registration date (placeholder)
    # In a real app, you'd add a 'date_registered' column to the User model.
    def get_user_registration_date_filter(user_id):
        # This is a placeholder. In a real app, you'd get this from the User model.
        return "N/A" # Or fetch from user.date_registered if it existed
    app.jinja_env.filters['get_user_registration_date'] = get_user_registration_date_filter

    return render_template_string(BASE_LAYOUT + USER_PROFILE_HTML, title='User Profile', user=current_user, orders=user_orders, now=datetime.utcnow())

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    """User messaging system - contact admin."""
    form = MessageForm()
    admin_user = User.query.filter_by(is_admin=True).first()
    if not admin_user:
        flash('Admin user not found. Messaging not available.', 'danger')
        return redirect(url_for('home'))

    user_to_admin_messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == admin_user.id)) |
        ((Message.sender_id == admin_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()

    if form.validate_on_submit():
        message = Message(
            sender_id=current_user.id,
            receiver_id=admin_user.id,
            message_text=form.message_text.data
        )
        db.session.add(message)
        db.session.commit()
        flash('Your message has been sent to the admin!', 'success')
        return redirect(url_for('messages'))

    return render_template_string(BASE_LAYOUT + USER_MESSAGES_HTML, title='Messages', form=form, messages=user_to_admin_messages, now=datetime.utcnow())

# --- Admin Routes ---
@app.route('/admin/dashboard', endpoint='admin_dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard - basic stats."""
    total_products = Product.query.count()
    total_users = User.query.count()
    total_orders = Order.query.count()
    pending_orders = Order.query.filter_by(status='Pending').count()
    return render_template_string(BASE_LAYOUT + ADMIN_DASHBOARD_HTML, title='Admin Dashboard',
                           total_products=total_products,
                           total_users=total_users,
                           total_orders=total_orders,
                           pending_orders=pending_orders, now=datetime.utcnow())

@app.route('/admin/products', endpoint='admin_products')
@admin_required
def admin_products():
    """Admin: View, Add, Edit, Delete Products."""
    products = Product.query.order_by(Product.name).all()
    return render_template_string(BASE_LAYOUT + ADMIN_PRODUCTS_HTML, title='Manage Products', products=products, now=datetime.utcnow())

@app.route('/admin/add_product', methods=['GET', 'POST'], endpoint='add_product')
@admin_required
def add_product():
    """Admin: Add a new product."""
    form = ProductForm()
    if form.validate_on_submit():
        image_file = request.files.get('image')
        filename = None
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            flash('Invalid image file or no file uploaded. Please upload a PNG, JPG, JPEG, or GIF.', 'warning')
            return render_template_string(BASE_LAYOUT + ADD_PRODUCT_HTML, title='Add Product', form=form, now=datetime.utcnow())

        product = Product(
            name=form.name.data,
            category=form.category.data,
            material=form.material.data,
            price=form.price.data,
            description=form.description.data,
            image_filename=filename
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_products'))
    return render_template_string(BASE_LAYOUT + ADD_PRODUCT_HTML, title='Add Product', form=form, now=datetime.utcnow())

@app.route('/admin/edit_product/<int:product_id>', methods=['GET', 'POST'], endpoint='edit_product')
@admin_required
def edit_product(product_id):
    """Admin: Edit an existing product."""
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)

    if form.validate_on_submit():
        product.name = form.name.data
        product.category = form.category.data
        product.material = form.material.data
        product.price = form.price.data
        product.description = form.description.data

        image_file = request.files.get('image')
        if image_file and image_file.filename: # Check if a file was actually selected
            if allowed_file(image_file.filename):
                # Delete old image if it exists
                if product.image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                filename = secure_filename(image_file.filename)
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                product.image_filename = filename
            else:
                flash('Invalid image file. Please upload a PNG, JPG, JPEG, or GIF.', 'warning')
                return render_template_string(BASE_LAYOUT + ADD_PRODUCT_HTML, title='Edit Product', form=form, product=product, now=datetime.utcnow())

        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('admin_products'))
    return render_template_string(BASE_LAYOUT + ADD_PRODUCT_HTML, title='Edit Product', form=form, product=product, now=datetime.utcnow())

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'], endpoint='delete_product')
@admin_required
def delete_product(product_id):
    """Admin: Delete a product."""
    product = Product.query.get_or_404(product_id)
    if product.image_filename:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/orders', endpoint='admin_orders')
@admin_required
def admin_orders():
    """Admin: View all orders."""
    orders = Order.query.order_by(Order.order_date.desc()).all()
    return render_template_string(BASE_LAYOUT + ADMIN_ORDERS_HTML, title='Manage Orders', orders=orders, now=datetime.utcnow())

@app.route('/admin/update_order_status/<int:order_id>', methods=['POST'], endpoint='update_order_status')
@admin_required
def update_order_status(order_id):
    """Admin: Update order status."""
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    if new_status in ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled']:
        order.status = new_status
        db.session.commit()
        flash(f'Order {order.id} status updated to {new_status}.', 'success')
    else:
        flash('Invalid status provided.', 'danger')
    return redirect(url_for('admin_orders'))

@app.route('/admin/users', endpoint='admin_users')
@admin_required
def admin_users():
    """Admin: View registered users."""
    users = User.query.order_by(User.username).all()
    # Add a custom filter to Jinja2 for getting user registration date (placeholder)
    def get_user_registration_date_filter(user_id):
        # This is a placeholder. In a real app, you'd add a 'date_registered' column to the User model
        # and return user.date_registered.strftime('%Y-%m-%d %H:%M')
        return "N/A"
    app.jinja_env.filters['get_user_registration_date'] = get_user_registration_date_filter
    return render_template_string(BASE_LAYOUT + ADMIN_USERS_HTML, title='Manage Users', users=users, now=datetime.utcnow())

@app.route('/admin/messages', methods=['GET', 'POST'], endpoint='admin_messages')
@admin_required
def admin_messages():
    """Admin: View and reply to user messages."""
    form = MessageForm()
    users_with_messages = db.session.query(User).join(Message, (User.id == Message.sender_id) | (User.id == Message.receiver_id)).filter(
        (Message.receiver_id == current_user.id) | (Message.sender_id == current_user.id)
    ).distinct().all()

    users_with_messages = [u for u in users_with_messages if not u.is_admin]

    selected_user_id = request.args.get('user_id', type=int)
    selected_user = None
    messages_with_selected_user = []

    if selected_user_id:
        selected_user = User.query.get(selected_user_id)
        if selected_user and not selected_user.is_admin:
            messages_with_selected_user = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == selected_user.id)) |
                ((Message.sender_id == selected_user.id) & (Message.receiver_id == current_user.id))
            ).order_by(Message.timestamp).all()

            for msg in messages_with_selected_user:
                if msg.sender_id == selected_user.id and msg.receiver_id == current_user.id and not msg.is_read:
                    msg.is_read = True
            db.session.commit()

    if form.validate_on_submit() and selected_user:
        message = Message(
            sender_id=current_user.id,
            receiver_id=selected_user.id,
            message_text=form.message_text.data
        )
        db.session.add(message)
        db.session.commit()
        flash(f'Message sent to {selected_user.username}!', 'success')
        return redirect(url_for('admin_messages', user_id=selected_user.id))

    return render_template_string(BASE_LAYOUT + ADMIN_MESSAGES_HTML, title='Admin Messages',
                           users_with_messages=users_with_messages,
                           selected_user=selected_user,
                           messages=messages_with_selected_user,
                           form=form, now=datetime.utcnow())

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error page."""
    return render_template_string(BASE_LAYOUT + ERROR_404_HTML, title='Page Not Found', now=datetime.utcnow()), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Custom 500 error page."""
    return render_template_string(BASE_LAYOUT + ERROR_500_HTML, title='Internal Server Error', now=datetime.utcnow()), 500

# --- Database Initialization (Run once to create tables) ---
@app.before_first_request
def create_tables():
    """Creates database tables and an initial admin user if they don't exist."""
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', email='admin@mdcreations.com', is_admin=True)
        admin_user.set_password('adminpassword') # IMPORTANT: Change this in production!
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created: admin/adminpassword")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', email='admin@mdcreations.com', is_admin=True)
            admin_user.set_password('adminpassword')
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created: admin/adminpassword")
    app.run(debug=True)
