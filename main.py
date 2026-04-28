
import io
import logging
import os
import random
import shutil
import smtplib
import subprocess
import ssl
import uuid
import copy
import re
from calendar import Calendar
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from PIL import Image, ImageOps
import pytz
from dateutil import parser
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory, Response, \
    flash
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_login import current_user, UserMixin
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from icalendar import Calendar, Event
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from sqlalchemy import func, or_
from sqlalchemy.orm import validates
from trio._tools.mypy_annotate import export
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from bs4 import BeautifulSoup

logging.basicConfig(level=logging.DEBUG)

# Set the template folder path
template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates')

# Set admin page API key
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'default_api_key')

# Path to the database folder and database file
database_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
database_path = os.path.join(database_folder, 'site.db')
instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'site.db')
icons_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons')

# Ensure the database folder exists
os.makedirs(database_folder, exist_ok=True)

# Check if site.db exists in the database folder, if not copy it from the instance folder
if not os.path.exists(database_path) and os.path.exists(instance_path):
    shutil.copyfile(instance_path, database_path)

# Set the static folder path inside the database folder
static_folder = os.path.join(database_folder, 'Static')
# Ensure the static folder exists
os.makedirs(static_folder, exist_ok=True)

# Set the uploads folder path inside the static folder
uploads_folder = os.path.join(static_folder, 'uploads')
# Ensure the uploads folder exists
os.makedirs(uploads_folder, exist_ok=True)

app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
app.secret_key = 'your_secret_key'  # Secret key for session management
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Set the SQLAlchemy database URI to use the database in the database folder
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)  # Add this line to initialize Flask-Migrate

MAX_UPLOAD_MB = 10
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

PUBLIC_MAX_WIDTH = 1600
THUMB_SIZE = (500, 500)
PUBLIC_QUALITY = 82
THUMB_QUALITY = 75

# Run Flask-Migrate commands to initialize and apply migrations
def run_migrations():
    migrate_command = ['flask', '--app', 'main', 'db', 'migrate', '-m', 'Migration maintenance.']
    upgrade_command = ['flask', '--app', 'main', 'db', 'upgrade']

    subprocess.run(migrate_command, cwd=os.path.dirname(__file__), check=True)
    subprocess.run(upgrade_command, cwd=os.path.dirname(__file__), check=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    websites = db.relationship('Website', backref='owner', lazy=True, cascade="all, delete-orphan")
    _is_active = db.Column(db.Boolean, default=True)  # Use a different attribute name

    @validates('username')
    def normalize_username(self, key, value):
        return value.strip().lower()

    @validates('email')
    def normalize_email(self, key, value):
        return value.strip().lower()

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True  # Assuming all users are authenticated

    @property
    def is_active(self):
        return self._is_active  # Implement according to your logic

    @property
    def is_anonymous(self):
        return False  # Assuming all users are not anonymous

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class EmailServerSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    smtp_host = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False, default=587)
    smtp_username = db.Column(db.String(255), nullable=False)
    smtp_password = db.Column(db.String(255), nullable=False)

    use_tls = db.Column(db.Boolean, default=True)
    use_ssl = db.Column(db.Boolean, default=False)

    from_email = db.Column(db.String(255), nullable=False)
    from_name = db.Column(db.String(255), nullable=True)

    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<EmailServerSettings {self.id}>"


from datetime import datetime

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=True)
    page_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'), nullable=True)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id'), nullable=False)

    sender_email = db.Column(db.String(255), nullable=False)
    recipient_email = db.Column(db.String(255), nullable=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)

    contact_form_title = db.Column(db.String(255), nullable=True)

    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    referrer = db.Column(db.Text, nullable=True)

    status = db.Column(db.String(50), nullable=False, default='pending')
    error_message = db.Column(db.Text, nullable=True)

    is_read = db.Column(db.Boolean, nullable=False, default=False)
    read_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sent_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<ContactMessage {self.id} {self.sender_email} {self.subject}>"

class WebsiteTag(db.Model):
    __tablename__ = 'website_tag'
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), primary_key=True)


class PageTag(db.Model):
    __tablename__ = 'page_tag'
    page_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), primary_key=True)


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)


class Website(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=True)  # Add description field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    public_page_contents = db.relationship('PublicPageContent', backref='website', lazy=True,
                                           cascade="all, delete-orphan")
    tags = db.relationship('Tag', secondary='website_tag', backref=db.backref('websites', lazy=True))

    background_color = db.Column(db.String(500), default='#ffffff')
    text_color = db.Column(db.String(20), default='#000000')
    background_image_url = db.Column(db.String(500), nullable=True)
    background_image_repeat = db.Column(db.Boolean, default=False)
    background_image_zoom = db.Column(db.Integer, default=100)

    public_navbar_items = db.Column(db.JSON, default=list)
    public_navbar_style = db.Column(db.JSON, default=dict)

    def __repr__(self):
        return f"<Website {self.id} - {self.name}>"


class PublicPageContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)

    page_folder_id = db.Column(db.Integer, db.ForeignKey('page_folder.id'), nullable=True)
    folder_sort_order = db.Column(db.Integer, default=0)

    page_folder = db.relationship('PageFolder', backref=db.backref('pages', lazy=True))

    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True)  # Add description field
    sort_order = db.Column(db.Integer, default=0)
    slug = db.Column(db.String(120), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('website_id', 'slug', name='unique_page_slug_per_website'),
    )
    # all_pictures = db.relationship('Picture', backref='page_content', lazy=True)
    # Use a 'secondary' join to find pictures through sections and then through section_images
    all_pictures = db.relationship(
        'Picture',
        secondary='join(PageSection, SectionImage, PageSection.id == SectionImage.section_id)',
        primaryjoin='PublicPageContent.id == PageSection.page_content_id',
        secondaryjoin='SectionImage.picture_id == Picture.id',
        viewonly=True
    )
    sections = db.relationship('PageSection', backref='public_page_content', lazy=True, cascade="all, delete-orphan")
    site_active_status = db.Column(db.Boolean, default=False)

    tags = db.relationship('Tag', secondary='page_tag', backref=db.backref('pages', lazy=True))
    background_color = db.Column(db.String(200), default='#ffffff')  # Default to white
    text_color = db.Column(db.String(20), default='#000000')  # Default to black

    messages = db.relationship('ContactMessage', backref='page', lazy=True)

    def __repr__(self):
        return f"<PublicPageContent {self.id}>"


class Row(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page_content_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'), nullable=False)
    row_number = db.Column(db.Integer, nullable=False)
    columns = db.relationship('Column', backref='row', cascade='all, delete-orphan', lazy=True)
    section_group_id = db.Column(db.Integer, db.ForeignKey('section_group.id'), nullable=True)

    def __repr__(self):
        return f"<Row {self.id} - Page Content: {self.page_content_id}, Row Number: {self.row_number}>"


class Column(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    row_id = db.Column(db.Integer, db.ForeignKey('row.id'), nullable=False)
    column_number = db.Column(db.Integer, nullable=False)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id'), nullable=True)
    width = db.Column(db.Integer, nullable=True)  # Add width attribute

    def __repr__(self):
        return (f"<Column {self.id} - Row: {self.row_id}, Column Number: {self.column_number}, "
                f"Section ID: {self.section_id}, Width: {self.width}>")


class PageSection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section_type = db.Column(db.String, nullable=False)
    order = db.Column(db.Integer)
    content = db.Column(db.JSON)
    page_content_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'))
    messages = db.relationship('ContactMessage', backref='section', lazy=True, cascade='all, delete-orphan')

    # Define a one-to-one relationship with Column
    column = db.relationship('Column', backref='section', uselist=False)

    def to_dict(self):
        column = self.column
        return {
            'id': self.id,
            'page_content_id': self.page_content_id,
            'order': self.order,
            'section_type': self.section_type,
            'content': self.content,
            'column_id': column.id if column else None,
            'column_number': column.column_number if column else None,
            'row_id': column.row.id if column else None,
            'row_number': column.row.row_number if column else None,
            'section_group_id': column.row.section_group_id if column and column.row else None,
            'width': column.width if column else None  # Include width
        }

    def __repr__(self):
        return f"<PageSection {self.id} - {self.section_type}>"

class SectionGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    page_content_id = db.Column(
        db.Integer,
        db.ForeignKey('public_page_content.id'),
        nullable=False
    )

    name = db.Column(db.String(100), default='Section Group')
    anchor_slug = db.Column(db.String(120), nullable=True)
    group_order = db.Column(db.Integer, default=0)

    background_color = db.Column(db.String(255), default='transparent')
    background_opacity = db.Column(db.Float, default=1)
    padding = db.Column(db.Integer, default=20)
    border_radius = db.Column(db.Integer, default=0)

    background_image_url = db.Column(db.String(500), nullable=True)
    background_image_size = db.Column(db.String(50), default='cover')
    background_image_position = db.Column(db.String(50), default='center')
    background_overlay_color = db.Column(db.String(50), default='transparent')
    background_overlay_opacity = db.Column(db.Float, default=0)

# class Picture(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     url = db.Column(db.String(1000))
#     order = db.Column(db.Integer)
#     page_content_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'))
#     section_id = db.Column(db.Integer, db.ForeignKey('page_section.id', name='fk_picture_section_id'))
#
#     def __repr__(self):
#         return f"<Picture {self.id}>"

class Picture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)          # optimized public image
    thumbnail_url = db.Column(db.String(500), nullable=True) # library/grid thumbnail
    original_url = db.Column(db.String(500), nullable=True)  # optional original
    # Track who owns the image
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Folder organization (Optional, can be null for "Main Dropbox")
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    # Metadata
    upload_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationship to the "Junction" table below
    section_usages = db.relationship('SectionImage', backref='image', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Picture {self.id} - {self.url}>"


class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # This allows pictures to be grouped
    pictures = db.relationship('Picture', backref='parent_folder', lazy=True)


class SectionImage(db.Model):
    __tablename__ = 'section_images'
    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id'), nullable=False)
    picture_id = db.Column(db.Integer, db.ForeignKey('picture.id'), nullable=False)
    # This is where 'order' lives now, so an image can be 1st in Section A
    # but 5th in Section B
    order = db.Column(db.Integer, default=0)


class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime)
    background_color = db.Column(db.String)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id', name='fk_calendar_event_page_content_id'))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'start': self.start.isoformat(),
            'end': self.end.isoformat() if self.end else None,
            'backgroundColor': self.background_color,
            'section_id': self.section_id
        }

class SavedColor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    color = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PageFolder(db.Model):
    __tablename__ = 'page_folder'

    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False, default='New Folder')
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    website = db.relationship('Website', backref=db.backref('page_folders', lazy=True, cascade='all, delete-orphan'))

    def active_page_count(self):
        return PublicPageContent.query.filter_by(
            page_folder_id=self.id,
            site_active_status=True
        ).count()

    def total_page_count(self):
        return PublicPageContent.query.filter_by(
            page_folder_id=self.id
        ).count()

# Hardcoded admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin')

# Set the upload folder path
UPLOAD_FOLDER = os.path.join(static_folder, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from flask import send_file
import requests
import json

# API endpoint
ollama_url = 'http://192.168.1.214:11434/api/generate'

from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())

def slugify(value):
    value = value.lower().strip()
    value = re.sub(r'[^a-z0-9\s-]', '', value)
    value = re.sub(r'[\s-]+', '-', value)
    return value.strip('-') or 'page'


def get_unique_slug(website_id, name, current_page_id=None):
    base_slug = slugify(name)
    slug = base_slug
    counter = 2

    while True:
        query = PublicPageContent.query.filter_by(
            website_id=website_id,
            slug=slug
        )

        if current_page_id:
            query = query.filter(PublicPageContent.id != current_page_id)

        existing = query.first()

        if not existing:
            return slug

        slug = f"{base_slug}-{counter}"
        counter += 1

def slugify_anchor(value):
    value = (value or '').strip().lower()
    value = re.sub(r'[^a-z0-9]+', '-', value)
    value = value.strip('-')
    return value or 'section-group'

@app.route('/update_page_colors/<int:page_id>', methods=['PUT'])
@login_required
def update_page_colors(page_id):
    data = request.get_json()

    background_color = (data.get('background_color') or '').strip()
    text_color = (data.get('text_color') or '').strip()

    page_content = PublicPageContent.query.get(page_id)
    if not page_content:
        return jsonify({'error': 'Page not found'}), 404

    if not background_color:
        return jsonify({'error': 'Background color is required'}), 400

    if not text_color:
        return jsonify({'error': 'Text color is required'}), 400

    page_content.background_color = background_color
    page_content.text_color = text_color

    db.session.commit()

    return jsonify({
        'message': 'Page colors updated successfully',
        'background_color': page_content.background_color,
        'text_color': page_content.text_color
    }), 200


#
# @app.route('/get_response_stream', methods=['POST'])
# @login_required
# def get_response_stream():
#     try:
#         # Get user input (prompt) from request JSON
#         request_data = request.get_json()
#         prompt = request_data.get('prompt', '')
#         code = request_data.get('code', '')
#         print("PROMPT: ", prompt)
#
#         adjusted_prompt = (
#                               "Generate code that includes embedded HTML, CSS, and JavaScript. Include all necessary "
#                               "header link sources, script sources, and stylesheets within the HTML code itself (no separate files). "
#                               "Ensure everything is encapsulated within <html>, <head>, <body>, <style>, <script> and tags. Your response should consist "
#                               "solely of code; do not include any explanatory text or comments. Do not wrap your code in the ``` marks. Here is the prompt: ") + prompt + (
#                               " Here is my current code for you to edit, only remove code if necessary to achieve the desired functionality: " + code)
#
#         # Construct payload with user-provided prompt
#         payload = {
#             "model": "deepseek-coder:6.7b",
#             "prompt": adjusted_prompt,
#             "stream": True  # Set stream to true to receive responses in a stream
#         }
#
#
#         # Send POST request to Ollama API with JSON payload and stream the response
#         response = requests.post(ollama_url, json=payload, stream=True)
#
#         # Ensure the request was successful (status code 200)
#         if response.status_code == 200:
#             # Stream the response content line by line
#             def generate_response():
#                 text = ''
#                 for line in response.iter_lines():
#                     if line:
#                         # Decode JSON from each line
#                         data = json.loads(line)
#
#                         # Extract the response portion from each JSON object
#                         if 'response' in data:
#                             yield data['response']
#                             print(data['response'], end='')
#                         else:
#                             yield "No response received\n"
#
#             # Return a streaming response to the client
#             return Response(generate_response(), content_type='text/plain')
#
#         else:
#             return f"Error: {response.status_code} - {response.text}"
#
#     except requests.exceptions.RequestException as e:
#         return f"Request failed: {e}"



@app.route('/capture', methods=['GET'])
def capture_webpage():
    url = request.args.get('url')

    # Configure headless Chrome options
    chrome_options = Options()
    chrome_options.add_argument('--headless')  # Run Chrome in headless mode
    chrome_options.add_argument('--disable-gpu')  # Disable GPU acceleration
    chrome_options.add_argument('--no-sandbox')  # Disable sandbox (necessary for running as root)

    # Initialize Chrome WebDriver
    driver = webdriver.Chrome(options=chrome_options)

    try:
        # Navigate to the URL
        driver.get(url)

        # Capture screenshot as binary data
        screenshot = driver.get_screenshot_as_png()

        # Return the captured screenshot to the client
        return send_file(io.BytesIO(screenshot), mimetype='image/png')

    finally:
        # Quit the WebDriver to free resources
        driver.quit()



def delete_associated_section_images(section_id):
    try:
        links = SectionImage.query.filter_by(section_id=section_id).all()
        for link in links:
            db.session.delete(link)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e


@app.route('/delete_row/<row_id>', methods=['DELETE'])
@login_required
def delete_row(row_id):
    try:
        row_id = int(row_id)  # Convert row_id to integer
        row = Row.query.get(row_id)
        print("Deleting Row:", row)
        if row:
            # Delete associated columns and update associated sections
            for column in row.columns:
                # Update all sections associated with the column to set column to null
                sections = PageSection.query.filter_by(column=column).all()
                print("Sections with removed columns: ", sections)
                # for section in sections:
                #     section.column = None

                for section in sections:
                    delete_associated_pictures(section.id)
                    db.session.delete(section)
                db.session.delete(column)
            # Delete associated columns
            columns = Column.query.filter_by(row_id=row_id).all()
            for column in columns:
                db.session.delete(column)
            db.session.delete(row)
            db.session.commit()
            print("Row and associated columns deleted successfully")
            return jsonify({'success': True}), 200
        else:
            return jsonify({'error': 'Row not found'}), 404
    except Exception as e:
        print("Error:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/delete_column/<int:column_id>', methods=['DELETE'])
@login_required
def delete_column(column_id):
    try:
        column = Column.query.get(column_id)
        if not column:
            return jsonify({'error': 'Column not found'}), 404

        row_id = column.row_id

        # Check if a section is associated with the column
        section = column.section
        if section:
            delete_associated_pictures(section.id)
            db.session.delete(section)

        # Deleting the column from the session to ensure it's removed
        db.session.delete(column)
        db.session.commit()
        # Call the function to delete undefined columns
        delete_undefined_columns()

        # Update widths of remaining columns
        columns = Column.query.filter_by(row_id=row_id).all()
        num_columns = len(columns)
        print("deleting column... numcolumns: ", num_columns)
        if num_columns > 0:
            new_width = 100 / num_columns
            for col in columns:
                col.width = new_width
                print("Adjusting Column width: ", col.id)
            db.session.commit()

        # Log the remaining columns associated with the row
        print(f"Columns remaining in row {row_id}:")
        for col in columns:
            print(f"Column ID: {col.id}, Width: {col.width}, Column Number: {col.column_number}")
        check_for_undefined_columns()
        # Respond with the updated columns to ensure frontend can sync
        return jsonify({'success': True, 'columns': [col.id for col in columns]}), 200
    except Exception as e:
        db.session.rollback()  # Rollback changes in case of error
        return jsonify({'error': str(e)}), 500


def delete_associated_pictures(section_id):
    try:
        links = SectionImage.query.filter_by(section_id=section_id).all()
        for link in links:
            db.session.delete(link)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise e


def check_for_undefined_columns():
    rows = Row.query.all()
    for row in rows:
        columns = Column.query.filter_by(row_id=row.id).all()
        column_numbers = [col.column_number for col in columns]
        max_column_number = max(column_numbers) if column_numbers else 0

        for i in range(1, max_column_number + 1):
            if i not in column_numbers:
                print(f"Undefined or missing column in row {row.id}: column number {i}")
            else:
                print(f"Column {i} in row {row.id} is defined")


def find_undefined_columns():
    rows = Row.query.all()
    for row in rows:
        columns = Column.query.filter_by(row_id=row.id).all()
        column_numbers = [col.column_number for col in columns]
        max_column_number = max(column_numbers) if column_numbers else 0

        undefined_columns = []
        for i in range(1, max_column_number + 1):
            if i not in column_numbers:
                undefined_columns.append(i)

        if undefined_columns:
            print(f"Undefined or missing columns in row {row.id}: {undefined_columns}")
        else:
            print(f"No undefined columns in row {row.id}")

    return undefined_columns


def delete_undefined_columns():
    rows = Row.query.all()
    for row in rows:
        columns = Column.query.filter_by(row_id=row.id).all()
        column_numbers = [col.column_number for col in columns]
        max_column_number = max(column_numbers) if column_numbers else 0

        # Identify undefined columns
        undefined_columns = []
        for i in range(1, max_column_number + 1):
            if i not in column_numbers:
                undefined_columns.append(i)

        # Log undefined columns
        if undefined_columns:
            print(f"Undefined or missing columns in row {row.id}: {undefined_columns}")

        # Delete undefined columns and renumber remaining columns if necessary
        for col in columns:
            if col.column_number in undefined_columns:
                db.session.delete(col)
            else:
                new_column_number = column_numbers.index(col.column_number) + 1
                col.column_number = new_column_number

        # Commit the changes to the database
        db.session.commit()

        # # Update the widths of remaining columns
        # remaining_columns = Column.query.filter_by(row_id=row.id).all()
        # num_columns = len(remaining_columns)
        # if num_columns > 0:
        #     new_width = 100 / num_columns
        #     for col in remaining_columns:
        #         col.width = new_width
        #     db.session.commit()


@app.route('/get_rows_and_columns/<int:page_content_id>', methods=['GET'])
@login_required
def get_rows_and_columns(page_content_id):
    # Fetch rows and columns associated with the given page_content_id
    rows = Row.query.filter_by(page_content_id=page_content_id).all()
    columns = Column.query.join(Row).filter(Row.page_content_id == page_content_id).all()
    # Convert rows and columns to dictionaries
    rows_data = [row.to_dict() for row in rows]
    columns_data = [column.to_dict() for column in columns]
    return jsonify({'rows': rows_data, 'columns': columns_data})

@app.route('/get_sections_and_structure/<int:page_content_id>', methods=['GET'])
@login_required
def get_sections_and_structure(page_content_id):
    try:
        page_content = PublicPageContent.query.filter_by(id=page_content_id).first()
        if not page_content:
            return jsonify({'error': 'Page content not found'}), 404

        sections = PageSection.query.filter_by(
            page_content_id=page_content_id
        ).order_by(PageSection.order).all()

        rows = Row.query.filter_by(
            page_content_id=page_content_id
        ).order_by(Row.row_number).all()

        columns = Column.query.join(Row).filter(
            Column.row_id == Row.id,
            Row.page_content_id == page_content_id
        ).order_by(Row.row_number, Column.column_number).all()

        section_groups = SectionGroup.query.filter_by(
            page_content_id=page_content_id
        ).order_by(SectionGroup.group_order).all()

        sections.sort(
            key=lambda x: (
                x.column.row.section_group_id or 0,
                x.column.row.row_number,
                x.order
            )
        )

        sections_data = [section.to_dict() for section in sections]

        rows_data = [
            {
                'id': row.id,
                'row_number': row.row_number,
                'section_group_id': row.section_group_id
            }
            for row in rows
        ]

        columns_data = [
            {
                'row_id': column.row_id,
                'row_number': column.row.row_number,
                'section_group_id': column.row.section_group_id,
                'column_number': column.column_number,
                'column_id': column.id,
                'width': column.width
            }
            for column in columns
        ]

        groups_data = [
            {
                'id': group.id,
                'name': group.name,
                'group_order': group.group_order,
                'background_color': group.background_color,
                'background_opacity': group.background_opacity,
                'padding': group.padding,
                'border_radius': group.border_radius,
                'background_image_url': group.background_image_url,
                'background_image_size': group.background_image_size or 'cover',
                'background_image_position': group.background_image_position or 'center',
                'background_overlay_color': group.background_overlay_color or '#000000',
                'background_overlay_opacity': group.background_overlay_opacity or 0
            }
            for group in section_groups
        ]

        website_data = {
            'id': page_content.website.id,
            'name': page_content.website.name,
            'description': page_content.website.description,
            'user_id': page_content.website.user_id,
            'tags': [tag.name for tag in page_content.website.tags]
        }

        response_data = {
            'sections': sections_data,
            'rows': rows_data,
            'columns': columns_data,
            'groups': groups_data,
            'website': website_data
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error retrieving sections and structure: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/create_section_group/<int:page_content_id>', methods=['POST'])
@login_required
def create_section_group(page_content_id):
    try:
        page_content = PublicPageContent.query.get_or_404(page_content_id)

        group_count = SectionGroup.query.filter_by(
            page_content_id=page_content.id
        ).count()

        new_group = SectionGroup(
            page_content_id=page_content.id,
            name=f'Section Group {group_count + 1}',
            group_order=group_count + 1,
            background_color='transparent',
            padding=0,
            border_radius=0
        )

        db.session.add(new_group)
        db.session.commit()

        return jsonify({
            'success': True,
            'group_id': new_group.id
        })

    except Exception as e:
        print(f"Error creating section group: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_section_group/<int:group_id>', methods=['DELETE'])
@login_required
def delete_section_group(group_id):
    try:
        group = SectionGroup.query.get_or_404(group_id)

        # Ungroup rows instead of deleting the rows
        rows = Row.query.filter_by(section_group_id=group.id).all()
        for row in rows:
            row.section_group_id = None

        db.session.delete(group)
        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        print(f"Error deleting section group: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_section_group/<int:group_id>', methods=['PUT'])
@login_required
def update_section_group(group_id):
    try:
        group = SectionGroup.query.get_or_404(group_id)
        data = request.get_json()

        name = data.get('name')
        background_color = data.get('background_color')
        padding = data.get('padding')
        border_radius = data.get('border_radius')

        if name is not None:
            group.name = name
            group.anchor_slug = slugify_anchor(name)

        if background_color is not None:
            group.background_color = background_color

        if padding is not None:
            group.padding = int(padding)

        if border_radius is not None:
            group.border_radius = int(border_radius)

        group.background_image_url = data.get('background_image_url') or None
        group.background_image_size = data.get('background_image_size') or 'cover'
        group.background_image_position = data.get('background_image_position') or 'center'
        group.background_overlay_color = data.get('background_overlay_color') or '#000000'
        group.background_overlay_opacity = float(data.get('background_overlay_opacity') or 0)

        db.session.commit()

        return jsonify({
            'success': True,
            'group': {
                'id': group.id,
                'name': group.name,
                'anchor_slug': group.anchor_slug
            }
        })

    except Exception as e:
        db.session.rollback()
        print("Error updating section group:", str(e))
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/move_row_to_group/<int:row_id>', methods=['PUT'])
@login_required
def move_row_to_group(row_id):
    row = Row.query.get_or_404(row_id)
    data = request.json

    row.section_group_id = data.get('section_group_id')
    db.session.commit()

    return jsonify({"success": True})

@app.route('/update_section_group_order', methods=['POST'])
@login_required
def update_section_group_order():
    try:
        data = request.get_json()
        group_ids = data.get('group_ids', [])

        for index, group_id in enumerate(group_ids, start=1):
            group = SectionGroup.query.get(group_id)
            if group:
                group.group_order = index

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        print(f"Error updating group order: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_row_order_and_groups', methods=['POST'])
@login_required
def update_row_order_and_groups():
    try:
        data = request.get_json()
        rows = data.get('rows', [])

        for row_item in rows:
            row = Row.query.get(row_item.get('row_id'))

            if row:
                row.row_number = row_item.get('row_number')
                row.section_group_id = row_item.get('section_group_id')

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        print(f"Error updating row order and groups: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_editor_group_and_row_order', methods=['POST'])
@login_required
def update_editor_group_and_row_order():
    try:
        data = request.get_json()

        group_ids = data.get('group_ids', [])
        rows = data.get('rows', [])

        for index, group_id in enumerate(group_ids, start=1):
            group = SectionGroup.query.get(group_id)
            if group:
                group.group_order = index

        for row_item in rows:
            row = Row.query.get(row_item.get('row_id'))
            if row:
                row.row_number = row_item.get('row_number')
                row.section_group_id = row_item.get('section_group_id')

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        print(f"Error updating editor order: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/add_column', methods=['POST'])
@login_required
def add_column():
    data = request.get_json()
    row_id = data.get('row_id')

    if not row_id:
        return jsonify({'error': 'Row ID is required'}), 400

    row = Row.query.get(row_id)
    if not row:
        return jsonify({'error': 'Row not found'}), 404

    # Get the next column number for the row
    next_column_number = len(row.columns) + 1

    # If it's the first column, set the width to 100%
    if next_column_number == 1:
        new_column_width = 100
    else:
        # Otherwise, recalculate the widths for all columns
        new_column_width = 100 / next_column_number
        for column in row.columns:
            column.width = new_column_width
        db.session.commit()  # Commit the width changes for existing columns

    # Create a new column with the calculated width
    new_column = Column(row_id=row_id, column_number=next_column_number, width=new_column_width)
    db.session.add(new_column)
    db.session.commit()

    return jsonify({'message': 'Column added successfully', 'column_id': new_column.id}), 200

@app.route('/add_row_to_group/<int:page_content_id>/<int:group_id>', methods=['POST'])
@login_required
def add_row_to_group(page_content_id, group_id):
    try:
        group = SectionGroup.query.get_or_404(group_id)

        last_row = Row.query.filter_by(
            page_content_id=page_content_id
        ).order_by(Row.row_number.desc()).first()

        new_row_number = (last_row.row_number + 1) if last_row else 1

        new_row = Row(
            page_content_id=page_content_id,
            row_number=new_row_number,
            section_group_id=group.id
        )

        db.session.add(new_row)
        db.session.flush()

        new_column = Column(
            row_id=new_row.id,
            column_number=1,
            width=100
        )

        db.session.add(new_column)
        db.session.commit()

        return jsonify({'success': True, 'row_id': new_row.id})

    except Exception as e:
        print(f"Error adding row to group: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update-column-widths', methods=['POST'])
@login_required
def update_column_widths():
    data = request.json
    prev_column_id = data['prevColumnId']
    new_width_prev = data['newWidthPrev']
    next_column_id = data['nextColumnId']
    new_width_next = data['newWidthNext']

    # Update the database with the new widths
    # Replace this with your actual database update logic
    update_column_width_in_db(prev_column_id, new_width_prev)
    update_column_width_in_db(next_column_id, new_width_next)

    return jsonify({'status': 'success'})


def update_column_width_in_db(column_id, new_width):
    column = Column.query.get(column_id)
    if column:
        column.width = new_width
        db.session.commit()
        print(f'Updated column {column_id} to width {new_width}%')
    else:
        print(f'Column {column_id} not found')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # 1. Block registration if any user already exists
    user_count = User.query.count()
    if user_count >= 1:
        flash('Registration is disabled. An admin account already exists.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('Please fill out all fields', 'error')
            return redirect(url_for('register'))

        # Standard check for duplicate emails (though technically redundant if only 1 user allowed)
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already in use', 'error')
            return redirect(url_for('register'))
        new_user = User(
            username=username,
            email=email
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Admin account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = User.query.filter_by(username=username).first()
#
#         if user and user.check_password(password):
#             session['logged_in'] = True  # Set the logged_in session variable
#             session['user_id'] = user.id  # Store the user ID in the session
#             flash('Logged in successfully', 'success')
#             return redirect(url_for('dashboard'))  # Redirect to the dashboard
#         else:
#             flash('Invalid username or password', 'error')
#             return redirect(url_for('login'))  # Redirect back to login on failure
#
#     return render_template('login.html')
#
#
# @app.route('/logout')
# def logout():
#     session.pop('user_id', None)
#     return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 1. Force setup if no user exists
    if User.query.count() == 0:
        return redirect(url_for('register'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        print("USER OBJECT RETRIEVED FROM DATABASE: ", user)

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required  # Ensure the user is logged in before they can log out
def logout():
    logout_user()  # Log out the user using Flask-Login
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


from flask_wtf.csrf import generate_csrf


@app.context_processor
def inject_current_website():
    if not current_user.is_authenticated:
        return {
            'current_website': None,
            'current_website_pages': []
        }

    website = Website.query.filter_by(user_id=current_user.id).first()

    if not website:
        return {
            'current_website': None,
            'current_website_pages': []
        }

    pages = PublicPageContent.query.filter_by(website_id=website.id) \
        .order_by(PublicPageContent.id).all()

    return {
        'current_website': website,
        'current_website_pages': pages
    }


@app.route('/admin/dashboard')
@login_required
def dashboard():
    user = current_user

    # This currently returns a list because of your model relationship
    websites = user.websites

    # Logic: If they have at least one, has_site is True
    has_site = len(websites) > 0

    website_pages = {}
    website_page_groups = {}
    website_page_folders = {}

    for website in websites:
        pages = PublicPageContent.query.filter_by(
            website_id=website.id
        ).order_by(
            PublicPageContent.sort_order,
            PublicPageContent.folder_sort_order,
            PublicPageContent.id
        ).all()

        folders = PageFolder.query.filter_by(
            website_id=website.id
        ).order_by(
            PageFolder.sort_order,
            PageFolder.id
        ).all()

        website_pages[website] = pages

        website_page_folders[website.id] = [
            {
                'id': folder.id,
                'name': folder.name,
                'sort_order': folder.sort_order,
                'active_count': sum(
                    1 for page in pages if page.page_folder_id == folder.id and page.site_active_status),
                'total_count': sum(1 for page in pages if page.page_folder_id == folder.id)
            }
            for folder in folders
        ]

        website_page_groups[website.id] = {}

        for page in pages:
            groups = SectionGroup.query.filter_by(
                page_content_id=page.id
            ).order_by(SectionGroup.group_order).all()

            website_page_groups[website.id][page.id] = [
                {
                    'id': group.id,
                    'name': group.name,
                    'anchor_slug': group.anchor_slug
                }
                for group in groups
                if group.anchor_slug
            ]

    csrf_token = generate_csrf()

    email_settings = get_email_settings()

    return render_template(
        'dashboard.html',
        websites=websites,
        website_pages=website_pages,
        website_page_groups=website_page_groups,
        website_page_folders=website_page_folders,
        user_has_website=has_site,
        csrf_token=csrf_token,
        email_settings=email_settings
    )

@app.route('/create_page_folder/<int:website_id>', methods=['POST'])
@login_required
def create_page_folder(website_id):
    website = Website.query.filter_by(
        id=website_id,
        user_id=current_user.id
    ).first_or_404()

    data = request.get_json() or {}
    name = (data.get('name') or 'New Folder').strip() or 'New Folder'

    max_order = db.session.query(func.max(PageFolder.sort_order)).filter_by(
        website_id=website.id
    ).scalar() or 0

    folder = PageFolder(
        website_id=website.id,
        name=name,
        sort_order=max_order + 1
    )

    db.session.add(folder)
    db.session.commit()

    return jsonify({
        'success': True,
        'folder': {
            'id': folder.id,
            'name': folder.name,
            'active_count': 0,
            'total_count': 0
        }
    })

@app.route('/rename_page_folder/<int:folder_id>', methods=['POST'])
@login_required
def rename_page_folder(folder_id):
    folder = PageFolder.query.get_or_404(folder_id)
    website = Website.query.filter_by(
        id=folder.website_id,
        user_id=current_user.id
    ).first_or_404()

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'Folder name is required.'}), 400

    folder.name = name
    db.session.commit()

    return jsonify({
        'success': True,
        'folder': {
            'id': folder.id,
            'name': folder.name
        }
    })

@app.route('/move_page_to_folder/<int:page_id>', methods=['POST'])
@login_required
def move_page_to_folder(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    website = Website.query.filter_by(
        id=page.website_id,
        user_id=current_user.id
    ).first_or_404()

    data = request.get_json() or {}
    folder_id = data.get('folder_id')

    if folder_id in ('', None, 'root'):
        page.page_folder_id = None

        max_order = db.session.query(func.max(PublicPageContent.sort_order)).filter_by(
            website_id=website.id,
            page_folder_id=None
        ).scalar() or 0

        page.sort_order = max_order + 1
        page.folder_sort_order = 0

    else:
        folder = PageFolder.query.filter_by(
            id=folder_id,
            website_id=website.id
        ).first_or_404()

        max_order = db.session.query(func.max(PublicPageContent.folder_sort_order)).filter_by(
            website_id=website.id,
            page_folder_id=folder.id
        ).scalar() or 0

        page.page_folder_id = folder.id
        page.folder_sort_order = max_order + 1

    db.session.commit()

    return jsonify({'success': True})


@app.route('/delete_page_folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_page_folder(folder_id):
    folder = PageFolder.query.get_or_404(folder_id)
    website = Website.query.filter_by(
        id=folder.website_id,
        user_id=current_user.id
    ).first_or_404()

    pages = PublicPageContent.query.filter_by(
        page_folder_id=folder.id
    ).all()

    max_order = db.session.query(func.max(PublicPageContent.sort_order)).filter_by(
        website_id=website.id,
        page_folder_id=None
    ).scalar() or 0

    for index, page in enumerate(pages, start=1):
        page.page_folder_id = None
        page.sort_order = max_order + index
        page.folder_sort_order = 0

    db.session.delete(folder)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/reorder_pages/<int:website_id>', methods=['POST'])
@login_required
def reorder_pages(website_id):
    website = Website.query.filter_by(
        id=website_id,
        user_id=current_user.id
    ).first_or_404()

    data = request.get_json() or {}
    page_ids = data.get('page_ids', [])
    folder_id = data.get('folder_id', 'root')

    resolved_folder_id = None

    if folder_id not in ('root', '', None):
        folder = PageFolder.query.filter_by(
            id=folder_id,
            website_id=website.id
        ).first_or_404()

        resolved_folder_id = folder.id

    for index, page_id in enumerate(page_ids):
        page = PublicPageContent.query.filter_by(
            id=page_id,
            website_id=website.id
        ).first()

        if not page:
            continue

        page.page_folder_id = resolved_folder_id

        if resolved_folder_id:
            page.folder_sort_order = index
        else:
            page.sort_order = index
            page.folder_sort_order = 0

    db.session.commit()

    return jsonify({'success': True})

@app.route('/admin/email_server_settings')
@login_required
def email_server_settings():
    user = current_user
    csrf_token = generate_csrf()

    email_settings = get_email_settings()

    return render_template(
        'email_server_settings.html',
        csrf_token=csrf_token,
        email_settings = email_settings
    )


def get_email_settings():
    return EmailServerSettings.query.first()

@app.route('/save_email_settings', methods=['POST'])
@login_required
def save_email_settings():
    settings = EmailServerSettings.query.first()

    if not settings:
        settings = EmailServerSettings()
        db.session.add(settings)

    settings.smtp_host = request.form.get('smtp_host', '').strip()
    settings.smtp_port = int(request.form.get('smtp_port', 587))
    settings.smtp_username = request.form.get('smtp_username', '').strip()

    raw_password = request.form.get('smtp_password', '').strip()
    if raw_password:
        settings.smtp_password = raw_password

    settings.from_email = request.form.get('from_email', '').strip()
    settings.from_name = request.form.get('from_name', '').strip()
    settings.use_tls = request.form.get('use_tls') == 'on'
    settings.use_ssl = request.form.get('use_ssl') == 'on'
    settings.is_active = request.form.get('is_active') == 'on'

    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'Email settings saved successfully'
    })


@app.route('/dashboard/messages')
@login_required
def messages_page():
    status_filter = request.args.get('status', 'all')
    read_filter = request.args.get('read', 'all')
    search = request.args.get('q', '').strip()

    query = ContactMessage.query.order_by(ContactMessage.created_at.desc())

    if status_filter != 'all':
        query = query.filter(ContactMessage.status == status_filter)

    if read_filter == 'unread':
        query = query.filter(ContactMessage.is_read == False)
    elif read_filter == 'read':
        query = query.filter(ContactMessage.is_read == True)

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                ContactMessage.sender_email.ilike(like),
                ContactMessage.subject.ilike(like),
                ContactMessage.body.ilike(like),
                ContactMessage.recipient_email.ilike(like)
            )
        )

    messages = query.all()
    unread_count = ContactMessage.query.filter_by(is_read=False).count()

    return render_template(
        'messages.html',
        messages=messages,
        unread_count=unread_count,
        status_filter=status_filter,
        read_filter=read_filter,
        search=search
    )

@app.route('/dashboard/messages/<int:message_id>/read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    msg = ContactMessage.query.get_or_404(message_id)

    if not msg.is_read:
        msg.is_read = True
        msg.read_at = datetime.utcnow()
        db.session.commit()

    return jsonify({'status': 'success'})

@app.route('/dashboard/messages/<int:message_id>/unread', methods=['POST'])
@login_required
def mark_message_unread(message_id):
    msg = ContactMessage.query.get_or_404(message_id)

    msg.is_read = False
    msg.read_at = None
    db.session.commit()

    return jsonify({'status': 'success'})

@app.route('/dashboard/messages/unread_count')
@login_required
def unread_messages_count():
    count = ContactMessage.query.filter_by(is_read=False).count()
    return jsonify({'count': count})

@app.route('/dashboard/messages/live')
@login_required
def messages_live():
    unread_count = ContactMessage.query.filter_by(is_read=False).count()

    latest_messages = (
        ContactMessage.query
        .order_by(ContactMessage.created_at.desc())
        .limit(50)
        .all()
    )

    return jsonify({
        'unread_count': unread_count,
        'messages': [
            {
                'id': msg.id,
                'sender_email': msg.sender_email,
                'recipient_email': msg.recipient_email,
                'subject': msg.subject,
                'body': msg.body,
                'body_preview': (msg.body[:120] + '...') if len(msg.body) > 120 else msg.body,
                'created_at': msg.created_at.strftime('%b %d, %Y %I:%M %p'),
                'is_read': msg.is_read,
                'status': msg.status,
                'error_message': msg.error_message,
                'ip_address': msg.ip_address,
                'referrer': msg.referrer,
                'contact_form_title': msg.contact_form_title,
            }
            for msg in latest_messages
        ]
    })


@app.route('/dashboard/messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = ContactMessage.query.get_or_404(message_id)
    db.session.delete(msg)
    db.session.commit()
    return jsonify({'status': 'success'})

@app.context_processor
def inject_unread_message_count():
    if current_user.is_authenticated:
        unread_message_count = ContactMessage.query.filter_by(is_read=False).count()
    else:
        unread_message_count = 0

    return dict(unread_message_count=unread_message_count)

@app.route('/send_email', methods=['POST'])
def send_email():
    sender_email = request.form.get('senders_email', '').strip()
    subject = request.form.get('message_subject', '').strip()
    body = request.form.get('message_body', '').strip()
    section_id = request.form.get('section_id')

    if not sender_email or not subject or not body or not section_id:
        return jsonify({
            'status': 'error',
            'message': 'Missing required fields'
        }), 400

    try:
        section_id = int(section_id)
    except ValueError:
        return jsonify({
            'status': 'error',
            'message': 'Invalid section id'
        }), 400

    email_settings = get_email_settings()
    if not email_settings or not email_settings.is_active:
        return jsonify({
            'status': 'error',
            'message': 'Email server is not configured'
        }), 400

    section = PageSection.query.get(section_id)
    if not section or section.section_type != 'contact_form':
        return jsonify({
            'status': 'error',
            'message': 'Invalid contact form section'
        }), 404

    recipient_email = None
    contact_form_title = None
    if section.content and isinstance(section.content, dict):
        recipient_email = section.content.get('email')
        contact_form_title = section.content.get('title')

    if not recipient_email:
        return jsonify({
            'status': 'error',
            'message': 'No recipient email found for this contact form'
        }), 400

    page_id = getattr(section, 'page_content_id', None)
    website_id = None
    if section.public_page_content:
        website_id = section.public_page_content.website_id

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

    user_agent = request.headers.get('User-Agent')
    referrer = request.referrer

    formatted_body = f"""
You have received a new message from your uwebia website contact form.

Sender Email: {sender_email}
Subject: {subject}

Message Body:
{body}
"""

    contact_message = ContactMessage(
        website_id=website_id,
        page_id=page_id,
        section_id=section_id,
        sender_email=sender_email,
        recipient_email=recipient_email,
        subject=subject,
        body=body,
        contact_form_title=contact_form_title,
        ip_address=ip_address,
        user_agent=user_agent,
        referrer=referrer,
        status='pending'
    )
    db.session.add(contact_message)
    db.session.commit()

    msg = MIMEMultipart()
    msg['From'] = (
        f"{email_settings.from_name} <{email_settings.from_email}>"
        if email_settings.from_name else email_settings.from_email
    )
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg['Reply-To'] = sender_email
    msg.attach(MIMEText(formatted_body, 'plain', 'utf-8'))

    try:
        if email_settings.use_ssl:
            server = smtplib.SMTP_SSL(
                email_settings.smtp_host,
                email_settings.smtp_port,
                timeout=10
            )
        else:
            server = smtplib.SMTP(
                email_settings.smtp_host,
                email_settings.smtp_port,
                timeout=10
            )
            if email_settings.use_tls:
                server.starttls()

        server.login(email_settings.smtp_username, email_settings.smtp_password)

        server.send_message(msg)

        server.quit()

        contact_message.status = 'sent'
        contact_message.sent_at = datetime.utcnow()
        contact_message.error_message = None
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message sent successfully'
        })

    except smtplib.SMTPAuthenticationError:
        contact_message.status = 'failed'
        contact_message.error_message = 'Email login failed. Check your username or app password.'
        db.session.commit()

        return jsonify({
            'status': 'error',
            'message': 'Email login failed. Check your username or app password.'
        }), 400

    except smtplib.SMTPConnectError:
        contact_message.status = 'failed'
        contact_message.error_message = 'Could not connect to the email server. Check host and port.'
        db.session.commit()

        return jsonify({
            'status': 'error',
            'message': 'Could not connect to the email server. Check host and port.'
        }), 400

    except smtplib.SMTPException as e:
        contact_message.status = 'failed'
        contact_message.error_message = f'Email sending failed: {str(e)}'
        db.session.commit()

        return jsonify({
            'status': 'error',
            'message': f'Email sending failed: {str(e)}'
        }), 400

    except ssl.SSLError:
        contact_message.status = 'failed'
        contact_message.error_message = 'SSL/TLS handshake failed. Check whether your port matches SSL or TLS settings.'
        db.session.commit()

        return jsonify({
            'status': 'error',
            'message': 'SSL/TLS handshake failed. Check whether your port matches SSL or TLS settings.'
        }), 400

    except Exception as e:
        import traceback
        traceback.print_exc()

        contact_message.status = 'failed'
        contact_message.error_message = f'Unexpected server error: {str(e)}'
        db.session.commit()

        return jsonify({
            'status': 'error',
            'message': 'Unexpected server error while sending email.'
        }), 500
@app.route('/send_test_email', methods=['POST'])
@login_required
def send_test_email():
    smtp_host = request.form.get('smtp_host', '').strip()
    smtp_port = request.form.get('smtp_port', '').strip()
    smtp_username = request.form.get('smtp_username', '').strip()
    smtp_password = request.form.get('smtp_password', '').strip()
    from_email = request.form.get('from_email', '').strip()
    from_name = request.form.get('from_name', '').strip()
    test_recipient = request.form.get('test_email', '').strip()

    use_tls = request.form.get('use_tls') == 'on'
    use_ssl = request.form.get('use_ssl') == 'on'
    is_active = request.form.get('is_active') == 'on'

    if not is_active:
        return jsonify({
            'status': 'error',
            'message': 'Email sending is currently disabled.'
        }), 400

    if not test_recipient:
        return jsonify({
            'status': 'error',
            'message': 'Test email address is required.'
        }), 400

    if not smtp_host or not smtp_port or not smtp_username or not smtp_password or not from_email:
        return jsonify({
            'status': 'error',
            'message': 'Missing required SMTP settings.'
        }), 400

    try:
        smtp_port = int(smtp_port)
    except ValueError:
        return jsonify({
            'status': 'error',
            'message': 'SMTP port must be a valid number.'
        }), 400

    if use_tls and use_ssl:
        return jsonify({
            'status': 'error',
            'message': 'Choose either TLS or SSL, not both.'
        }), 400

    subject = 'Uwebia Test Email'
    body = """This is a test email from your Uwebia email server configuration.

If you received this, your SMTP settings are working.
"""

    msg = MIMEMultipart()
    msg['From'] = f"{from_name} <{from_email}>" if from_name else from_email
    msg['To'] = test_recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=10
            )
        else:
            server = smtplib.SMTP(
                smtp_host,
                smtp_port,
                timeout=10
            )
            if use_tls:
                server.starttls()

        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()

        return jsonify({
            'status': 'success',
            'message': f'Test email sent successfully to {test_recipient}.'
        })

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            'status': 'error',
            'message': 'Email login failed. Check your username or app password.'
        }), 400

    except smtplib.SMTPConnectError:
        return jsonify({
            'status': 'error',
            'message': 'Could not connect to the email server. Check host and port.'
        }), 400

    except smtplib.SMTPServerDisconnected:
        return jsonify({
            'status': 'error',
            'message': 'The email server disconnected unexpectedly. Check TLS/SSL settings and port.'
        }), 400

    except smtplib.SMTPRecipientsRefused:
        return jsonify({
            'status': 'error',
            'message': 'The test recipient email address was refused by the server.'
        }), 400

    except smtplib.SMTPException as e:
        return jsonify({
            'status': 'error',
            'message': f'Email sending failed: {str(e)}'
        }), 400

    except ssl.SSLError:
        return jsonify({
            'status': 'error',
            'message': 'SSL/TLS handshake failed. Check whether your port matches SSL or TLS settings.'
        }), 400

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Unexpected server error while sending test email: {str(e)}'
        }), 500

@app.route('/create_website', methods=['POST'])
@login_required
def create_website():
    # Check if a website already exists for this user
    existing_site = Website.query.filter_by(user_id=current_user.id).first()

    if existing_site:
        # You could flash a message or redirect back to their existing site
        return "You already have a website!", 400
    name = request.form['name']
    description = request.form['description']
    tags = request.form.get('tags', '')  # Get tags from the form, default to empty string if not provided

    user = current_user
    new_website = Website(name=name, owner=user, description=description)
    db.session.add(new_website)
    db.session.commit()

    home_page = PublicPageContent(
        website_id=new_website.id,
        name='Home',
        description='Root page',
        slug='home',
        sort_order=0,
        site_active_status=False
    )

    db.session.add(home_page)
    db.session.commit()

    # Process tags
    if tags:
        tag_names = [tag.strip() for tag in tags.split(',')]
        for tag_name in tag_names:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.session.add(tag)
                db.session.commit()
            new_website.tags.append(tag)

    db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/<string:page_slug>')
def public_page_by_slug(page_slug):
    website = Website.query.first()

    if not website:
        return render_template('no_site_found.html'), 404

    page = PublicPageContent.query.filter_by(
        website_id=website.id,
        slug=page_slug
    ).first()

    if not page:
        return "Page Not Found", 404

    if not page.site_active_status:
        return "Site Inactive", 404

    return render_public_page(website, page)

@app.route('/create_page/<int:website_id>', methods=['GET', 'POST'])
@login_required
def create_page(website_id):
    website = Website.query.get_or_404(website_id)
    if website.owner.id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})

    if request.method == 'POST':
        # Handle form submission to create a new page
        name = request.form['name']
        description = request.form['description']
        tags = request.form.get('tags', '')  # Get tags from the form, default to empty string if not provided

        new_content = PublicPageContent(name=name, description=description, website_id=website_id, slug=get_unique_slug(website_id, name))
        db.session.add(new_content)
        db.session.commit()

        # Process tags
        if tags:
            tag_names = [tag.strip() for tag in tags.split(',')]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                new_content.tags.append(tag)

        db.session.commit()

        return redirect(url_for('page_editor', website_id=website_id, page_id=new_content.id))

    # Render template for GET request
    return render_template('create_page.html', website=website)

@app.route('/edit_website/<int:website_id>', methods=['POST'])
@login_required
def edit_website(website_id):
    website = Website.query.get_or_404(website_id)

    if website.user_id != current_user.id:
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized access'
        }), 403

    data = request.get_json()

    website.name = data.get('name', website.name)
    website.description = data.get('description', website.description)
    website.background_color = data.get('background_color', website.background_color)
    website.text_color = data.get('text_color', website.text_color)
    website.public_navbar_items = data.get(
        'public_navbar_items',
        website.public_navbar_items
    )

    # Replace tags
    new_tags = data.get('tags', '')
    tag_names = [tag.strip() for tag in new_tags.split(',') if tag.strip()]

    website.tags.clear()

    for tag_name in tag_names:
        tag = Tag.query.filter_by(name=tag_name).first()

        if not tag:
            tag = Tag(name=tag_name)
            db.session.add(tag)

        website.tags.append(tag)

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Website updated successfully'
    })

@app.route('/edit_website_style/<int:website_id>', methods=['POST'])
@login_required
def edit_website_style(website_id):
    website = Website.query.get_or_404(website_id)

    if website.user_id != current_user.id:
        return jsonify({
            'success': False,
            'message': 'Unauthorized access'
        }), 403

    data = request.get_json()

    website.background_color = data.get('background_color', website.background_color)
    website.text_color = data.get('text_color', website.text_color)

    website.background_image_url = data.get('background_image_url') or None
    website.background_image_repeat = bool(data.get('background_image_repeat', False))

    try:
        zoom = int(data.get('background_image_zoom') or 100)
    except ValueError:
        zoom = 100

    website.background_image_zoom = max(25, min(1000, zoom))

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Website style updated successfully',
        'background_color': website.background_color,
        'text_color': website.text_color,
        'background_image_url': website.background_image_url,
        'background_image_repeat': website.background_image_repeat,
        'background_image_zoom': website.background_image_zoom
    })

@app.route('/edit_page/<int:website_id>/<int:page_id>', methods=['POST'])
@login_required
def edit_page(website_id, page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    new_name = request.form.get('name')
    new_tags = request.form.get('tags')
    new_description = request.form.get('description')  # Get the updated description from the form

    # Update page name
    if new_name:
        page.name = new_name

        if page.slug != 'home':
            page.slug = get_unique_slug(website_id, new_name, current_page_id=page.id)

    # Update page description
    if new_description:
        page.description = new_description

    # Update page tags
    if new_tags:
        tag_names = [tag.strip() for tag in new_tags.split(',')]
        page.tags.clear()
        for tag_name in tag_names:
            tag = Tag.query.filter_by(name=tag_name).first() or Tag(name=tag_name)
            page.tags.append(tag)

    db.session.commit()
    return jsonify({'message': 'Page updated successfully'})

@app.route('/duplicate_page/<int:website_id>/<int:page_id>', methods=['POST'])
@login_required
def duplicate_page(website_id, page_id):
    original_page = PublicPageContent.query.filter_by(
        id=page_id,
        website_id=website_id
    ).first_or_404()

    # Create copied page
    new_page = PublicPageContent(
        website_id=original_page.website_id,
        name=f"{original_page.name} Copy",
        description=original_page.description,
        site_active_status=False,
        background_color=original_page.background_color,
        text_color=original_page.text_color,
        slug=get_unique_slug(original_page.website_id, f"{original_page.name} Copy")
    )
    db.session.add(new_page)
    db.session.flush()  # get new_page.id

    # Copy tags
    for tag in original_page.tags:
        new_page.tags.append(tag)

    # -----------------------------
    # Copy section groups first
    # -----------------------------
    group_map = {}

    original_groups = SectionGroup.query.filter_by(
        page_content_id=original_page.id
    ).all()

    for old_group in original_groups:
        new_group = SectionGroup(
            page_content_id=new_page.id,
            name=old_group.name,
            anchor_slug=old_group.anchor_slug,
            group_order=old_group.group_order,
            background_color=old_group.background_color,
            background_opacity=old_group.background_opacity,
            padding=old_group.padding,
            border_radius=old_group.border_radius
        )
        db.session.add(new_group)
        db.session.flush()

        group_map[old_group.id] = new_group.id

    # -----------------------------
    # Copy sections second
    # -----------------------------
    section_map = {}

    original_sections = PageSection.query.filter_by(
        page_content_id=original_page.id
    ).all()


    for old_section in original_sections:
        new_section = PageSection(
            section_type=old_section.section_type,
            order=old_section.order,
            content=copy.deepcopy(old_section.content),
            page_content_id=new_page.id
        )
        db.session.add(new_section)
        db.session.flush()

        section_map[old_section.id] = new_section.id

        # Copy section images
        original_images = SectionImage.query.filter_by(section_id=old_section.id).all()
        for old_img in original_images:
            new_img = SectionImage(
                section_id=new_section.id,
                picture_id=old_img.picture_id,
                order=old_img.order
            )
            db.session.add(new_img)

        # Copy calendar events
        original_events = CalendarEvent.query.filter_by(section_id=old_section.id).all()
        for old_event in original_events:
            new_event = CalendarEvent(
                title=old_event.title,
                description=old_event.description,
                start=old_event.start,
                end=old_event.end,
                background_color=old_event.background_color,
                section_id=new_section.id
            )
            db.session.add(new_event)

    # -----------------------------
    # Copy rows and columns
    # -----------------------------
    original_rows = Row.query.filter_by(page_content_id=original_page.id).all()

    for old_row in original_rows:
        new_row = Row(
            page_content_id=new_page.id,
            row_number=old_row.row_number,
            section_group_id=group_map.get(old_row.section_group_id) if old_row.section_group_id else None
        )
        db.session.add(new_row)
        db.session.flush()

        original_columns = Column.query.filter_by(row_id=old_row.id).all()
        for old_column in original_columns:
            new_column = Column(
                row_id=new_row.id,
                column_number=old_column.column_number,
                width=old_column.width,
                section_id=section_map.get(old_column.section_id) if old_column.section_id else None
            )
            db.session.add(new_column)

    db.session.commit()
    return '', 200


@app.route('/replace_page/<int:target_page_id>/<int:source_page_id>', methods=['POST'])
@login_required
def replace_page(target_page_id, source_page_id):
    target_page = PublicPageContent.query.get_or_404(target_page_id)
    source_page = PublicPageContent.query.get_or_404(source_page_id)

    target_website = Website.query.get_or_404(target_page.website_id)
    source_website = Website.query.get_or_404(source_page.website_id)

    if target_website.user_id != current_user.id or source_website.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    # Optional: prevent replacing a page with itself
    if target_page.id == source_page.id:
        return jsonify({"error": "Cannot replace a page with itself."}), 400

    # Update page-level fields
    # target_page.name = source_page.name
    target_page.description = source_page.description
    target_page.background_color = source_page.background_color
    target_page.text_color = source_page.text_color
    # target_page.site_active_status = source_page.site_active_status

    # Replace tags
    target_page.tags.clear()
    for tag in source_page.tags:
        target_page.tags.append(tag)

    # Delete target page’s existing layout/content
    Row.query.filter_by(page_content_id=target_page.id).delete()
    SectionGroup.query.filter_by(page_content_id=target_page.id).delete()

    old_target_sections = PageSection.query.filter_by(page_content_id=target_page.id).all()
    for section in old_target_sections:
        SectionImage.query.filter_by(section_id=section.id).delete()
        CalendarEvent.query.filter_by(section_id=section.id).delete()
        db.session.delete(section)

    db.session.flush()

    # -----------------------------
    # Copy source groups first
    # -----------------------------
    group_map = {}

    source_groups = SectionGroup.query.filter_by(
        page_content_id=source_page.id
    ).all()

    for old_group in source_groups:
        new_group = SectionGroup(
            page_content_id=target_page.id,
            name=old_group.name,
            anchor_slug=old_group.anchor_slug,
            group_order=old_group.group_order,
            background_color=old_group.background_color,
            background_opacity=old_group.background_opacity,
            padding=old_group.padding,
            border_radius=old_group.border_radius
        )
        db.session.add(new_group)
        db.session.flush()

        group_map[old_group.id] = new_group.id

    # Copy source sections
    section_map = {}

    source_sections = PageSection.query.filter_by(page_content_id=source_page.id).all()

    for old_section in source_sections:
        new_section = PageSection(
            section_type=old_section.section_type,
            order=old_section.order,
            content=copy.deepcopy(old_section.content),
            page_content_id=target_page.id
        )
        db.session.add(new_section)
        db.session.flush()

        section_map[old_section.id] = new_section.id

        # Copy section images
        source_images = SectionImage.query.filter_by(section_id=old_section.id).all()
        for old_img in source_images:
            db.session.add(SectionImage(
                section_id=new_section.id,
                picture_id=old_img.picture_id,
                order=old_img.order
            ))

        # Copy calendar events
        source_events = CalendarEvent.query.filter_by(section_id=old_section.id).all()
        for old_event in source_events:
            db.session.add(CalendarEvent(
                title=old_event.title,
                description=old_event.description,
                start=old_event.start,
                end=old_event.end,
                background_color=old_event.background_color,
                section_id=new_section.id
            ))

    # Copy source rows and columns
    source_rows = Row.query.filter_by(page_content_id=source_page.id).all()

    for old_row in source_rows:
        new_row = Row(
            page_content_id=target_page.id,
            row_number=old_row.row_number,
            section_group_id=group_map.get(old_row.section_group_id) if old_row.section_group_id else None
        )
        db.session.add(new_row)
        db.session.flush()

        source_columns = Column.query.filter_by(row_id=old_row.id).all()

        for old_column in source_columns:
            db.session.add(Column(
                row_id=new_row.id,
                column_number=old_column.column_number,
                width=old_column.width,
                section_id=section_map.get(old_column.section_id) if old_column.section_id else None
            ))

    db.session.commit()

    return jsonify({"success": True})

def get_copy_name(website_id, original_name):
    base_name = f"{original_name} Copy"
    existing_names = {
        p.name for p in PublicPageContent.query.filter_by(website_id=website_id).all()
    }

    if base_name not in existing_names:
        return base_name

    i = 2
    while f"{base_name} {i}" in existing_names:
        i += 1

    return f"{base_name} {i}"

@app.route('/remove_tag/page/<int:website_id>/<string:tag_name>', methods=['POST'])
@login_required
def remove_website_tag(website_id, tag_name):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})

    website = Website.query.get_or_404(website_id)
    if website.owner.id != session['user_id']:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})

    tag = Tag.query.filter_by(name=tag_name).first()
    if not tag:
        return jsonify({'status': 'error', 'message': 'Tag not found'})

    website.tags.remove(tag)
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/get_website_details/<int:website_id>', methods=['GET'])
def get_website_details(website_id):
    website = Website.query.get_or_404(website_id)
    # Assuming the website details include name and tags
    return jsonify(
        {'name': website.name, 'description': website.description, 'tags': [tag.name for tag in website.tags]})


@app.route('/get_page_details/<int:page_id>', methods=['GET'])
def get_page_details(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    # Assuming the page details include name and tags
    return jsonify({'name': page.name, 'description': page.description, 'tags': [tag.name for tag in page.tags]})


@app.route('/api/page/<int:website_id>/pages', methods=['GET'])
def get_pages_for_website(website_id):
    try:
        website = Website.query.get_or_404(website_id)
        pages = PublicPageContent.query.filter_by(website_id=website_id).all()
        pages_data = [{'id': page.id, 'name': page.name} for page in pages]
        return jsonify({'pages': pages_data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/<int:website_id>/<int:page_id>')
@login_required
def page_editor(website_id, page_id):
    website = Website.query.get_or_404(website_id)
    if website.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})

    content = PublicPageContent.query.get_or_404(page_id)
    if content.website_id != website.id:
        return jsonify({'status': 'error', 'message': 'Page does not belong to this website'})

    site_active_status = content.site_active_status
    sections = PageSection.query.filter_by(page_content_id=page_id).order_by(PageSection.order).all()

    navbar_pages = PublicPageContent.query.filter_by(
        website_id=website.id
    ).order_by(PublicPageContent.name).all()

    for section in sections:
        if section.column:
            section.row_id = section.column.row_id
            section.row_number = section.column.row.row_number
            section.column_id = section.column.id
            section.column_number = section.column.column_number

    return render_template(
        'page_editor.html',
        site_active_status=site_active_status,
        sections=sections,
        page_id=page_id,
        website=website,
        page_content=content,
        navbar_pages=navbar_pages
    )


@app.route('/delete_page/<int:website_id>/<int:page_id>', methods=['POST'])
@login_required
def delete_page(website_id, page_id):
    page = PublicPageContent.query.filter_by(id=page_id, website_id=website_id).first()
    if page:
        if page.slug == 'home':
            return jsonify({
                'error': 'The root page cannot be deleted. Use Replace Page to change its content or edit it directly.'
            }), 400
        # Check if the user owns the website
        website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
        if website:
            try:
                # Delete all associated rows and columns
                rows = Row.query.filter_by(page_content_id=page.id).all()
                for row in rows:
                    db.session.delete(row)

                # Delete the page itself
                db.session.delete(page)
                db.session.commit()
                return jsonify({'message': 'Page deleted successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': str(e)}), 500
        else:
            return jsonify({'error': 'You are not authorized to delete this page'}), 403
    else:
        return jsonify({'error': 'Page not found'}), 404


@app.route('/delete_website/<int:website_id>', methods=['POST'])
@login_required
def delete_website(website_id):
    website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()
    if website:
        try:
            # Delete all pages associated with the website
            pages = PublicPageContent.query.filter_by(website_id=website_id).all()
            for page in pages:
                rows = Row.query.filter_by(page_content_id=page.id).all()
                for row in rows:
                    db.session.delete(row)
                db.session.delete(page)

            # Delete the website itself
            db.session.delete(website)
            db.session.commit()
            return jsonify({'message': 'Website deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': 'Website not found or you are not authorized to delete it'}), 404


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/swap_section_positions/<int:first_section_id>/<int:second_section_id>', methods=['PUT'])
@login_required
def swap_section_positions(first_section_id, second_section_id):
    first_column = Column.query.filter_by(section_id=first_section_id).first()
    second_column = Column.query.filter_by(section_id=second_section_id).first()

    if not first_column or not second_column:
        return jsonify({'error': 'One or both sections not found in columns'}), 404

    first_column.section_id, second_column.section_id = second_column.section_id, first_column.section_id

    db.session.commit()
    return jsonify({'message': 'Sections position swapped successfully'}), 200


@app.route('/update_section_position/<int:section_id>', methods=['PUT'])
@login_required
def update_section_position(section_id):
    data = request.get_json()
    column_id = data.get('columnId')

    section = PageSection.query.get(section_id)
    target_column = Column.query.get(column_id)

    if not section:
        return jsonify({'error': 'Section not found'}), 404

    if not target_column:
        return jsonify({'error': 'Target column not found'}), 404

    if target_column.section_id is not None and target_column.section_id != section_id:
        return jsonify({'error': 'Column already contains a section'}), 400

    current_column = Column.query.filter_by(section_id=section_id).first()

    if current_column and current_column.id != target_column.id:
        current_column.section_id = None

    target_column.section_id = section_id

    db.session.commit()

    return jsonify({
        'message': 'Section position updated successfully',
        'row_id': target_column.row_id,
        'column_id': target_column.id
    }), 200


@app.route('/move_section_to_new_row/<int:section_id>', methods=['PUT'])
@login_required
def move_section_to_new_row(section_id):
    data = request.get_json()
    target_row_id = data.get('targetRowId')

    section = PageSection.query.get(section_id)
    target_row = Row.query.get(target_row_id)

    if not section:
        return jsonify({'error': 'Section not found'}), 404

    if not target_row:
        return jsonify({'error': 'Target row not found'}), 404

    empty_column = None
    for col in target_row.columns:
        if col.section_id is None:
            empty_column = col
            break

    if not empty_column:
        next_col_num = max([c.column_number for c in target_row.columns], default=0) + 1
        empty_column = Column(
            row_id=target_row.id,
            column_number=next_col_num,
            section_id=None,
            width=100
        )
        db.session.add(empty_column)
        db.session.flush()

    current_column = Column.query.filter_by(section_id=section_id).first()
    if current_column:
        current_column.section_id = None

    empty_column.section_id = section_id

    db.session.commit()

    return jsonify({'message': 'Section moved successfully'})


@app.route('/insert_section_before_row/<int:section_id>', methods=['PUT'])
@login_required
def insert_section_before_row(section_id):
    data = request.get_json()
    target_row_id = data.get('targetRowId')

    section = PageSection.query.get(section_id)
    target_row = Row.query.get(target_row_id)

    if not section:
        return jsonify({'error': 'Section not found'}), 404

    if not target_row:
        return jsonify({'error': 'Target row not found'}), 404

    try:
        insert_row_number = target_row.row_number
        page_content_id = target_row.page_content_id

        rows_to_shift = (
            Row.query
            .filter(
                Row.page_content_id == page_content_id,
                Row.row_number >= insert_row_number
            )
            .order_by(Row.row_number.desc())
            .all()
        )

        for row in rows_to_shift:
            row.row_number += 1

        new_row = Row(
            page_content_id=page_content_id,
            row_number=insert_row_number
        )
        db.session.add(new_row)
        db.session.flush()

        new_column = Column(
            row_id=new_row.id,
            column_number=1,
            section_id=None,
            width=100
        )
        db.session.add(new_column)
        db.session.flush()

        current_column = Column.query.filter_by(section_id=section_id).first()
        if current_column:
            current_column.section_id = None

        new_column.section_id = section_id

        db.session.commit()
        return jsonify({'message': 'Section inserted into new row successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Assuming you have a Flask app instance named 'app'
@app.route('/get_sections/<int:page_content_id>', methods=['GET'])
@login_required
def get_sections(page_content_id):
    # Query the PublicPageContent to ensure it exists and to get the website
    content = PublicPageContent.query.get_or_404(page_content_id)
    website = content.website

    # Check if the current user is authorized to modify this page
    if website.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403
    # Query PageSection objects filtered by page_content_id and sort them by order number
    sections = PageSection.query.filter_by(page_content_id=page_content_id).order_by(PageSection.order).all()

    # Convert each PageSection object to a dictionary
    sections_data = [section.to_dict() for section in sections]
    print("get sections data: ", sections_data)

    # Return the sections data as JSON
    return jsonify(sections_data)  # Directly return the list of sections


@app.route('/page/<int:page_id>/add_section', methods=['POST'])
@login_required
def add_section(page_id):
    # Query the PublicPageContent to ensure it exists and to get the website
    content = PublicPageContent.query.get_or_404(page_id)
    website = content.website

    # Check if the current user is authorized to modify this page
    if website.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 403
    data = request.json

    row_id = data.get('row_id')
    column_id = data.get('column_id')

    columns = Column.query.filter_by(row_id=row_id).all()
    num_columns = len(columns)

    # if num_columns > 1:
    #     new_width = 100 / (num_columns + 1)
    #     for col in columns:
    #         col.width = new_width
    #     db.session.commit()  # Commit the width changes for existing columns

    if row_id is not None and column_id is not None:
        # If both row_id and column_id are provided, use them directly
        row = Row.query.get(row_id)
        column = Column.query.get(column_id)
    else:
        # If either row_id or column_id is not provided, create new ones
        max_row = db.session.query(func.max(Row.row_number)).filter_by(page_content_id=page_id).scalar()
        new_row_number = max_row + 1 if max_row is not None else 1

        new_row = Row(page_content_id=page_id, row_number=new_row_number)
        db.session.add(new_row)
        db.session.commit()

        # Create a new column
        new_column = Column(row_id=new_row.id, column_number=1, width=100)
        db.session.add(new_column)
        db.session.commit()

        row = new_row
        column = new_column

    # Create a new PageSection object and assign the column object
    section_content = data['content']
    new_section = PageSection(
        section_type=data['section_type'],
        order=1,  # You may adjust this according to your logic
        content=section_content,
        page_content_id=page_id,
        column=column
    )
    db.session.add(new_section)
    db.session.commit()

    return jsonify({'message': 'Section added successfully'}), 201


@app.route('/add_row_above/<int:row_id>', methods=['POST'])
@login_required
def add_row_above(row_id):
    print("ADD ROW ABOVE: ", row_id)
    try:
        # Get the current row
        current_row = Row.query.get_or_404(row_id)
        current_row_number = current_row.row_number

        # Fetch and sort rows to increment based on row_number
        rows_to_increment = Row.query.filter(
            Row.page_content_id == current_row.page_content_id,
            Row.row_number >= current_row.row_number
        ).order_by(Row.row_number.asc()).all()

        # Increment the row numbers of the current row and all rows below it
        for row in rows_to_increment:
            row.row_number += 1
            print(f"Incremented Row {row.id} to Row Number {row.row_number}")

        # Create a new row at the original position of the current row
        new_row = Row(
            page_content_id=current_row.page_content_id,
            row_number=current_row_number
        )
        db.session.add(new_row)
        db.session.flush()  # Flush to get the new_row ID
        print(f"New Row ID: {new_row.id}, Row Number: {new_row.row_number}")

        # Create a default column for the new row
        new_column = Column(
            row_id=new_row.id,
            column_number=1,  # Default column number, adjust as necessary
            width=100
        )
        db.session.add(new_column)

        # Commit the changes to the database
        db.session.commit()
        print("Commit successful")

        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/page/<int:page_id>/remove_section/<int:section_id>', methods=['DELETE'])
@login_required
def remove_section(page_id, section_id):
    section = PageSection.query.get_or_404(section_id)
    removed_order = section.order

    delete_associated_section_images(section.id)

    db.session.delete(section)
    db.session.commit()

    remaining_sections = PageSection.query.filter(
        PageSection.page_content_id == page_id,
        PageSection.order > removed_order
    ).all()

    for s in remaining_sections:
        s.order -= 1

    db.session.commit()
    return jsonify({'message': 'Section removed successfully'}), 200


@app.route('/page/<int:page_id>/reorder_sections', methods=['POST'])
@login_required
def reorder_sections(page_id):
    data = request.json
    for item in data['sections']:
        section = PageSection.query.get(item['id'])
        section.order = item['order']
    db.session.commit()
    return jsonify({'message': 'Sections reordered successfully'}), 200


# Route to handle updating section order
@app.route('/update_section_order', methods=['POST'])
@login_required
def update_section_order():
    section_id = request.args.get('section_id')
    new_order = request.args.get('new_order')

    # Check if both section_id and new_order are provided
    if section_id is None or new_order is None:
        return 'Both section_id and new_order are required', 400

    # Convert new_order to integer
    try:
        new_order = int(new_order)
    except ValueError:
        return 'Invalid new_order value', 400

    # Fetch the section from the database
    section = PageSection.query.get(section_id)
    if section:
        # Update the order number
        section.order = new_order
        db.session.commit()
        return 'Section order updated successfully', 200
    else:
        return 'Section not found', 404


@app.route('/library/upload', methods=['POST'])
@login_required
def library_upload():
    files = request.files.getlist('picture')
    folder_id = request.form.get('folder_id')

    user_folder = os.path.join(uploads_folder, str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)

    for file in files:
        if not file or not allowed_file(file.filename):
            continue

        # size check
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size > MAX_UPLOAD_BYTES:
            return jsonify({
                'status': 'error',
                'error': f'"{file.filename}" exceeds the {MAX_UPLOAD_MB} MB limit.'
            }), 400

        try:
            saved = save_optimized_versions(file, user_folder)

            public_url = url_for(
                'static',
                filename=f'uploads/{current_user.id}/{saved["public_filename"]}'
            )
            thumb_url = url_for(
                'static',
                filename=f'uploads/{current_user.id}/{saved["thumb_filename"]}'
            )

            new_pic = Picture(
                url=public_url,
                thumbnail_url=thumb_url,
                user_id=current_user.id,
                folder_id=folder_id
            )
            db.session.add(new_pic)

        except Exception as e:
            return jsonify({
                'status': 'error',
                'error': f'Failed to process "{file.filename}": {str(e)}'
            }), 400

    db.session.commit()
    return jsonify({'status': 'success'})

def ensure_rgb(image: Image.Image) -> Image.Image:
    if image.mode in ("RGBA", "LA"):
        background = Image.new("RGB", image.size, (255, 255, 255))
        background.paste(image, mask=image.getchannel("A"))
        return background
    if image.mode != "RGB":
        return image.convert("RGB")
    return image


def save_optimized_versions(file_storage, output_dir: str) -> dict:
    os.makedirs(output_dir, exist_ok=True)

    base_name = uuid.uuid4().hex

    with Image.open(file_storage.stream) as img:
        img = ImageOps.exif_transpose(img)
        img = ensure_rgb(img)

        # Public image
        public_img = img.copy()
        if public_img.width > PUBLIC_MAX_WIDTH:
            ratio = PUBLIC_MAX_WIDTH / public_img.width
            new_height = int(public_img.height * ratio)
            public_img = public_img.resize((PUBLIC_MAX_WIDTH, new_height), Image.LANCZOS)

        public_filename = f"{base_name}.webp"
        public_path = os.path.join(output_dir, public_filename)
        public_img.save(public_path, "WEBP", quality=PUBLIC_QUALITY, method=6)

        # Thumbnail
        thumb_img = img.copy()
        thumb_img.thumbnail(THUMB_SIZE, Image.LANCZOS)

        thumb_filename = f"{base_name}_thumb.webp"
        thumb_path = os.path.join(output_dir, thumb_filename)
        thumb_img.save(thumb_path, "WEBP", quality=THUMB_QUALITY, method=6)

    return {
        "public_filename": public_filename,
        "thumb_filename": thumb_filename,
    }

@app.route('/get_library_root', methods=['GET'])
@login_required
def get_library_root():
    all_folders = Folder.query.filter_by(user_id=current_user.id).all()
    root_images = Picture.query.filter_by(user_id=current_user.id, folder_id=None).all()
    return jsonify({
        'folders': [{'id': f.id, 'name': f.name} for f in all_folders],
        'images': [{'id': i.id, 'url': i.url} for i in root_images]
    })


@app.route('/get_library_folder/<int:folder_id>', methods=['GET'])
@login_required
def get_library_folder(folder_id):
    # Verify the folder belongs to the user
    folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()

    # Get images inside this specific folder
    images = Picture.query.filter_by(user_id=current_user.id, folder_id=folder_id).all()

    return jsonify({
        'folders': [],  # Assuming no nested folders for now
        'images': [{'id': i.id, 'url': i.url} for i in images]
    })


@app.route('/dashboard/library')
@login_required
def photo_library():
    # Fetch top-level folders and pictures not in a folder (the "Dropbox")
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    root_pictures = Picture.query.filter_by(
        user_id=current_user.id,
        folder_id=None
    ).order_by(Picture.upload_date.desc()).all()

    return render_template('photo_library.html',
                           folders=folders,
                           root_pictures=root_pictures)


def update_images_section(section, form_data):
    section.content = {
        'image_layout': form_data.get('image_layout', 'single'),
        'image_fit': form_data.get('image_fit', 'cover'),
        'image_radius': form_data.get('image_radius', '10'),
        'show_thumbnails': form_data.get('show_thumbnails') == 'on',
        'autoplay': form_data.get('autoplay') == 'on'
    }

    # Optional but recommended: migrate old section types forward.
    section.section_type = 'images'

    return section

@app.route('/section/add_image', methods=['POST'])
@login_required
def link_image_to_section():
    data = request.json
    section_id = data.get('section_id')
    picture_id = data.get('picture_id')

    # Add to junction table
    link = SectionImage(section_id=section_id, picture_id=picture_id)
    db.session.add(link)
    db.session.commit()
    return jsonify({'status': 'success'})


@app.route('/update_public_images', methods=['POST'])
@login_required
def update_public_images():
    # if not session.get('logged_in'):
    #     print('not logged in')
    #     return jsonify({'status': 'error', 'message': 'Unauthorized'})
    #
    # user_id = session.get('user_id')

    # current_user is guaranteed to exist and be logged in
    user_id = current_user.id  # or .get_id() depending on your User model

    print(f"Logged in as user {user_id}")
    print('UserID: ', user_id)
    if not user_id:
        print('missing user id')
        return jsonify({'status': 'error', 'message': 'User ID is missing'})

    if 'picture' not in request.files:
        print('missing file?')
        return jsonify({'status': 'error', 'message': 'No file part'})

    files = request.files.getlist('picture')  # Get the list of files

    section_id = request.form.get('section_id')  # Get the section ID from the form
    print("Section ID: ", section_id)

    if not section_id:
        return jsonify({'status': 'error', 'message': 'Section ID is missing'})

    # Fetch the section type using the section ID
    section = PageSection.query.filter_by(id=section_id).first()
    if not section:
        return jsonify({'status': 'error', 'message': 'Section not found'})

    section_type = section.section_type

    if section_type == 'image':
        if len(files) != 1:
            return jsonify({'status': 'error', 'message': 'Only one file allowed for "image" section'})

        file = files[0]  # Get the first file object
        user_folder = os.path.join(uploads_folder, str(user_id))
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'})

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(user_folder, filename)
            file.save(filepath)
            picture_url = url_for('static', filename='uploads/' + str(user_id) + '/' + filename)

            # Get the existing picture for the section, if any
            existing_picture = Picture.query.filter_by(section_id=section_id).first()

            if existing_picture:
                # Update the existing picture URL
                existing_picture.url = picture_url
            else:
                # Create a new picture entry
                max_order = db.session.query(func.max(Picture.order)).filter_by(section_id=section_id).scalar() or 0
                picture = Picture(url=picture_url, order=max_order + 1, section_id=section_id)
                db.session.add(picture)

            db.session.commit()

            return jsonify({'status': 'success', 'message': 'Image uploaded successfully', 'section_id': section_id})

        else:
            return jsonify({'status': 'error', 'message': 'Invalid file format'})

    elif section_type == 'image_gallery':
        user_folder = os.path.join(uploads_folder, str(user_id))
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        picture_urls = []  # Store picture URLs

        for file in files:
            if file.filename == '':
                print('Upload Image Not Found')
                return jsonify({'status': 'error', 'message': 'No selected file'})

            if file and allowed_file(file.filename):
                print('Upload Image Found')
                filename = secure_filename(file.filename)
                filepath = os.path.join(user_folder, filename)
                file.save(filepath)
                picture_url = url_for('static', filename='uploads/' + str(user_id) + '/' + filename)

                max_order = db.session.query(func.max(Picture.order)).filter_by(section_id=section_id).scalar() or 0
                picture = Picture(url=picture_url, order=max_order + 1, section_id=section_id)
                db.session.add(picture)
                db.session.commit()
                picture_urls.append(picture_url)

            else:
                return jsonify({'status': 'error', 'message': 'Invalid file format'})

        return jsonify({'status': 'success', 'message': 'Images uploaded successfully', 'section_id': section_id})

    else:
        return jsonify({'status': 'error', 'message': 'Invalid section type'})


@app.route('/get_uploaded_images')
@login_required
def get_uploaded_images():
    section_id = request.args.get('section_id', type=int)
    if not section_id:
        return jsonify({'status': 'error', 'message': 'Section ID is missing'})

    results = (
        db.session.query(Picture, SectionImage)
        .join(SectionImage, Picture.id == SectionImage.picture_id)
        .filter(SectionImage.section_id == section_id)
        .order_by(SectionImage.order)
        .all()
    )

    images_data = [{
        'id': pic.id,  # Picture ID
        'link_id': link.id,  # SectionImage ID
        'url': pic.url,
        'order': link.order
    } for pic, link in results]

    return jsonify({'images': images_data})


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(uploads_folder, filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename})
    else:
        return jsonify({'error': 'Invalid file format'})


@app.route('/delete_image', methods=['POST'])
@login_required
def delete_image():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # Get the image ID from the request
    image_id = request.json.get('id')

    # Find the image in the database
    image = Picture.query.get(image_id)

    if image:
        try:
            # Remove the image from the database
            db.session.delete(image)
            db.session.commit()

            # Remove the image file from the filesystem
            image_path = os.path.join(uploads_folder, os.path.basename(image.url))
            if os.path.exists(image_path):
                os.remove(image_path)

            return jsonify({'status': 'success', 'message': 'Image deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)})
    else:
        return jsonify({'status': 'error', 'message': 'Image not found'})


from flask import render_template, request, jsonify, url_for
from flask_login import login_required, current_user
import os


@app.route('/add_images_from_library', methods=['POST'])
@login_required
def add_images_from_library():
    data = request.json
    section_id = data.get('section_id')
    image_ids = data.get('image_ids')  # IDs from the Picture table

    for img_id in image_ids:
        lib_pic = Picture.query.get(img_id)
        # Create a new reference or copy the entry for this section
        # Logic depends on if your SectionImages table is separate
        new_entry = SectionImage(section_id=section_id, picture_id=lib_pic.id)
        db.session.add(new_entry)

    db.session.commit()
    return jsonify({'status': 'success'})


# Create a new folder
@app.route('/library/create_folder', methods=['POST'])
@login_required
def create_folder():
    data = request.json
    name = data.get('name')
    if not name:
        return jsonify({'status': 'error', 'message': 'Name is required'}), 400

    new_folder = Folder(name=name, user_id=current_user.id)
    db.session.add(new_folder)
    db.session.commit()
    return jsonify({'status': 'success', 'folder_id': new_folder.id})


# View a specific folder
@app.route('/dashboard/library/folder/<int:folder_id>')
@login_required
def view_folder(folder_id):
    folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()
    folders = Folder.query.filter_by(user_id=current_user.id).all()  # For sidebar/navigation
    pictures = Picture.query.filter_by(folder_id=folder_id).all()

    return render_template('photo_library.html',
                           folders=folders,
                           root_pictures=pictures,
                           current_folder=folder)


# Move image to folder
@app.route('/library/move_image', methods=['POST'])
@login_required
def move_image():
    data = request.json
    image_id = data.get('image_id')
    folder_id = data.get('folder_id')

    # If dropped on 'Main Library', set folder_id to None
    if folder_id == "root":
        folder_id = None

    image = Picture.query.filter_by(id=image_id, user_id=current_user.id).first()
    if image:
        image.folder_id = folder_id
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 404


# Revamped Delete (Handles database and physical file)
@app.route('/library/delete_image/<int:image_id>', methods=['POST'])
@login_required
def delete_library_image(image_id):
    image = Picture.query.filter_by(id=image_id, user_id=current_user.id).first()
    if not image:
        return jsonify({'status': 'error', 'message': 'Not found'}), 404

    try:
        # 1. Determine local path from URL
        # URL is usually: /static/uploads/1/image.jpg
        # We need: project_root/static/uploads/1/image.jpg
        relative_path = image.url.lstrip('/')
        full_path = os.path.join(app.root_path, relative_path)

        # 2. Delete file from disk
        if os.path.exists(full_path):
            os.remove(full_path)

        # 3. Delete from DB (cascades to section_usages)
        db.session.delete(image)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/update_public_text', methods=['POST'])
@login_required
def update_public_text():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # Get the values from the request form
    header_text = request.form.get('header_text')
    button_text = request.form.get('button_text')
    button_link = request.form.get('button_link')
    # Convert button_enabled to boolean
    button_enabled = request.form.get('button_enabled') == 'on'

    # Update database with new values
    content = PublicPageContent.query.first()
    if content is not None:
        content.header_text = header_text
        content.button_text = button_text
        content.button_link = button_link
        content.button_enabled = button_enabled

        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Public page content updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update content'})


@app.route('/update_youtube_video', methods=['POST'])
@login_required
def update_youtube_video():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # Get the values from the request form
    section_id = request.form.get('section_id')
    youtube_url = request.form.get('youtube_url')

    # Update the specified section with the new YouTube URL
    section = PageSection.query.filter_by(id=section_id).first()
    if section is not None:
        section.content['youtube_url'] = youtube_url

        db.session.commit()
        return jsonify({'status': 'success', 'message': 'YouTube video URL updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update YouTube video URL'})


@app.route('/update_page_header', methods=['POST'])
@login_required
def update_page_header():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # Get the values from the request form
    header_text = request.form.get('header_text')

    # Update database with new values
    content = PublicPageContent.query.first()
    if content is not None:
        content.header_text = header_text

        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Public page header updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update header'})


@app.route('/update_page_body', methods=['POST'])
@login_required
def update_page_body():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    text = request.form.get('text')

    # Update database with new values
    content = PublicPageContent.query.first()
    if content is not None:

        content.text = text
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Public page content updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update content'})


@app.route('/update_contact_form', methods=['POST'])
@login_required
def update_contact_form():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # Get the values from the request form
    contact_form_title = request.form.get('contact_form_title')
    contact_email = request.form.get('contact_email')  # Corrected here
    contact_form_enabled = request.form.get('contact_form_enabled') == 'on'

    # Update database with new values
    content = PublicPageContent.query.first()
    if content is not None:
        content.contact_form_title = contact_form_title
        content.contact_email = contact_email  # Corrected here
        content.contact_form_enabled = contact_form_enabled
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Public page content updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update content'})


# @app.route('/update_map_marker', methods=['POST'])
# @login_required
# def update_map_marker():
#     data = request.form
#     latitude = data.get('latitude', type=float)
#     longitude = data.get('longitude', type=float)
#     map_enabled = data.get('map_enabled') == 'on'
#     map_marker_label = data.get('map_marker_label')
#
#     # Assuming there is only one PublicPageContent entry, or you need to specify which one to update
#     page_content = PublicPageContent.query.first()
#     if page_content:
#         page_content.latitude = latitude
#         page_content.longitude = longitude
#         page_content.map_enabled = map_enabled
#         page_content.map_marker_label = map_marker_label
#         db.session.commit()
#         return jsonify({'status': 'success', 'message': 'Map marker updated successfully'}), 200
#     else:
#         return jsonify({'status': 'error', 'message': 'Page content not found'}), 404


@app.route('/static/<path:filename>')
def serve_static(filename):
    print("Request for static file:", filename)
    return send_from_directory(app.static_folder, filename)

def render_public_page(website, page, is_preview=False):
    sections = PageSection.query.filter_by(
        page_content_id=page.id
    ).order_by(PageSection.order).all()

    pictures_by_section = {}

    for section in sections:
        results = (
            db.session.query(Picture, SectionImage)
            .join(SectionImage, Picture.id == SectionImage.picture_id)
            .filter(SectionImage.section_id == section.id)
            .order_by(SectionImage.order)
            .all()
        )

        pictures_by_section[section.id] = [
            picture.url for picture, link in results
        ]

    section_groups = SectionGroup.query.filter_by(
        page_content_id=page.id
    ).order_by(SectionGroup.group_order).all()

    public_page_content = {
        'page_id': page.id,
        'page_slug': page.slug,
        'current_page_url': url_for('public_page_by_slug', page_slug=page.slug),
        'sections': [section.to_dict() for section in sections],
        'groups': [
    {
        'id': group.id,
        'name': group.name,
        'anchor_slug': group.anchor_slug,
        'group_order': group.group_order,

        'background_color': group.background_color or 'transparent',
        'background_opacity': group.background_opacity,

        'padding': group.padding,
        'border_radius': group.border_radius,

        'background_image_url': group.background_image_url,
        'background_image_size': group.background_image_size or 'cover',
        'background_image_position': group.background_image_position or 'center',
        'background_overlay_color': group.background_overlay_color or 'transparent',
        'background_overlay_opacity': group.background_overlay_opacity or 0
    }
    for group in section_groups
],
        'pictures_by_section': pictures_by_section,
        'is_preview': is_preview
    }


    return render_template(
        'public.html',
        website=website,
        content=public_page_content
    )

@app.route('/')
def home_page():
    website = Website.query.first()

    if not website:
        return render_template('no_site_found.html'), 404

    page = PublicPageContent.query.filter_by(
        website_id=website.id,
        slug='home'
    ).first()

    if not page:
        return "Root page not found. Please create a page with the slug /home.", 404

    if not page.site_active_status:
        return "Root page is not published.", 404

    return render_public_page(website, page)
#
# @app.route('/page/<int:website_id>/<int:page_id>')
# def public_page(website_id, page_id):
#     content = PublicPageContent.query.filter_by(website_id=website_id, id=page_id).first()
#
#     if content is None:
#         return jsonify({'status': 'error', 'message': 'Public page content not found'})
#
#     if not content.site_active_status:
#         return jsonify({'status': 'error', 'message': 'Public page is currently inactive'})
#
#     sections = PageSection.query.filter_by(page_content_id=content.id).order_by(PageSection.order).all()
#
#     pictures_by_section = {}
#     for section in sections:
#         results = (
#             db.session.query(Picture, SectionImage)
#             .join(SectionImage, Picture.id == SectionImage.picture_id)
#             .filter(SectionImage.section_id == section.id)
#             .order_by(SectionImage.order)
#             .all()
#         )
#
#         pictures_by_section[section.id] = [picture.url for picture, link in results]
#
#     sections_dict = [section.to_dict() for section in sections]
#
#     public_page_content = {
#         'page_id': content.id,
#         'sections': sections_dict,
#         'pictures_by_section': pictures_by_section,
#         'background_color': content.background_color,
#         'text_color': content.text_color
#     }
#
#     print("Sections Data:", sections_dict)
#     print("Pictures by Section:", pictures_by_section)
#     print("COLORS: ", content.background_color, ", ", content.text_color)
#
#     return render_template('public.html', content=public_page_content)

@app.route('/page/<int:website_id>/<int:page_id>')
def public_page(website_id, page_id):
    page = PublicPageContent.query.filter_by(
        website_id=website_id,
        id=page_id
    ).first_or_404()

    return redirect(url_for('public_page_by_slug', page_slug=page.slug))

@app.route('/preview_page/<int:website_id>/<int:page_id>')
@login_required
def preview_page(website_id, page_id):
    # Use db.session.get for SQLAlchemy 2.0 compatibility
    website = db.session.get(Website, website_id)
    if not website or website.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 404

    content = PublicPageContent.query.filter_by(website_id=website_id, id=page_id).first()

    if content is None:
        return jsonify({'status': 'error', 'message': 'Public page content not found'})

    sections = PageSection.query.filter_by(page_content_id=content.id).order_by(PageSection.order).all()

    pictures_by_section = {}
    for section in sections:
        # NEW LOGIC: Join SectionImage and Picture to get the URLs for this specific section
        section_pictures = db.session.query(Picture.url).join(
            SectionImage, Picture.id == SectionImage.picture_id
        ).filter(
            SectionImage.section_id == section.id
        ).order_by(
            SectionImage.order
        ).all()

        # .all() returns a list of tuples, e.g., [('url1',), ('url2',)],
        # so we flatten it to a list of strings
        pictures_by_section[section.id] = [p.url for p in section_pictures]

    sections_dict = [section.to_dict() for section in sections]

    # public_page_content = {
    #     'page_id': content.id,
    #     'sections': sections_dict,
    #     'pictures_by_section': pictures_by_section,
    #     'background_color': content.background_color,
    #     'text_color': content.text_color
    # }
    #
    # return render_template('public.html', content=public_page_content)

    section_groups = SectionGroup.query.filter_by(
        page_content_id=content.id
    ).order_by(SectionGroup.group_order).all()

    public_page_content = {
        'page_id': content.id,
        'sections': sections_dict,
        'page_slug': content.slug,
        'current_page_url': url_for('public_page_by_slug', page_slug=content.slug),
        'groups': [
    {
        'id': group.id,
        'name': group.name,
        'anchor_slug': group.anchor_slug,
        'group_order': group.group_order,

        'background_color': group.background_color or 'transparent',
        'background_opacity': group.background_opacity,

        'padding': group.padding,
        'border_radius': group.border_radius,

        'background_image_url': group.background_image_url,
        'background_image_size': group.background_image_size or 'cover',
        'background_image_position': group.background_image_position or 'center',
        'background_overlay_color': group.background_overlay_color or 'transparent',
        'background_overlay_opacity': group.background_overlay_opacity or 0
    }
    for group in section_groups
],
        'pictures_by_section': pictures_by_section,
        'is_preview': True
    }

    return render_template(
        'public.html',
        website=website,
        content=public_page_content
    )


def update_map_section(section, form_data):
    latitude = form_data.get('latitude')
    longitude = form_data.get('longitude')
    map_marker_label = form_data.get('map_marker_label')
    map_enabled = form_data.get('map_enabled') == 'on'

    def parse_coordinate(value, min_val, max_val):
        try:
            val = float(value)
            if val < min_val or val > max_val:
                return None
            return val
        except (TypeError, ValueError):
            return None

    lat = parse_coordinate(latitude, -90, 90)
    lng = parse_coordinate(longitude, -180, 180)

    # Optional: fallback to previous values if invalid
    existing = section.content or {}

    section.content = {
        'latitude': lat if lat is not None else existing.get('latitude'),
        'longitude': lng if lng is not None else existing.get('longitude'),
        'marker_label': map_marker_label,
        'enabled': map_enabled
    }

    return section

@app.route('/preview_navbar/<int:website_id>')
@login_required
def preview_navbar(website_id):
    website = db.session.get(Website, website_id)

    if not website or website.user_id != current_user.id:
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 404

    return render_template(
        'navbar_preview.html',
        website=website
    )
def update_text_section(section, form_data):
    import json

    html_content = form_data.get('text', '')
    delta_raw = form_data.get('delta')

    background_color = form_data.get('background_color', '#000000')
    background_opacity = form_data.get('background_opacity', '0')
    padding = form_data.get('padding', '20')
    border_radius = form_data.get('border_radius', '10')
    box_shadow = form_data.get('box_shadow', 'medium')

    soup = BeautifulSoup(html_content, 'html.parser')

    for clipboard in soup.find_all('div', class_='ql-clipboard'):
        clipboard.decompose()

    for tooltip in soup.find_all('div', class_='ql-tooltip'):
        tooltip.decompose()

    try:
        delta_data = json.loads(delta_raw) if delta_raw else None
    except json.JSONDecodeError:
        delta_data = None

    section.content = {
        'html': str(soup),
        'delta': delta_data,
        'background_color': background_color,
        'background_opacity': background_opacity,
        'padding': padding,
        'border_radius': border_radius,
        'box_shadow': box_shadow
    }

    return section

# def update_code_section(section, form_data):
#     text_content = form_data.get('text')
#     section.content = {'text': text_content}
#     return section


def update_button_section(section, form_data):
    button_text = form_data.get('button_text')
    button_link = form_data.get('button_link')
    button_enabled = form_data.get('button_enabled') == 'on'

    section.content = {
        'text': button_text,
        'link': button_link,
        'enabled': button_enabled
    }
    return section


def update_youtube_video_section(section, form_data):
    youtube_url = form_data.get('youtube_url')
    section.content = {'youtube_url': youtube_url}
    return section


def update_contact_section(section, form_data):
    contact_form_title = form_data.get('contact_form_title')
    contact_email = form_data.get('contact_email')
    contact_form_enabled = form_data.get('contact_form_enabled') == 'on'

    section.content = {
        'title': contact_form_title,
        'email': contact_email,
        'enabled': contact_form_enabled
    }
    return section


def update_header_section(section, form_data):
    header_text = form_data.get('header_text')
    section.content = {'text': header_text}
    return section


def update_contact_section(section, form_data):
    contact_form_title = form_data.get('contact_form_title')
    contact_email = form_data.get('contact_email')
    contact_form_enabled = form_data.get('contact_form_enabled') == 'on'

    section.content = {
        'title': contact_form_title,
        'email': contact_email,
        'enabled': contact_form_enabled
    }
    return section

@app.route('/edit_public_navbar/<int:website_id>', methods=['POST'])
@login_required
def edit_public_navbar(website_id):
    website = Website.query.get_or_404(website_id)

    if website.user_id != current_user.id:
        return jsonify({
            'success': False,
            'message': 'Unauthorized access'
        }), 403

    data = request.get_json() or {}
    navbar_items = data.get('public_navbar_items', [])

    website.public_navbar_items = navbar_items

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Public navbar updated successfully',
        'public_navbar_items': website.public_navbar_items
    })

def update_navbar_section(section, form_data):
    navbar_names = form_data.getlist('navbar_names')
    navbar_urls = form_data.getlist('navbar_urls')

    # Combine names and URLs into a list of dictionaries
    navbar_items = [{'name': name, 'url': url} for name, url in zip(navbar_names, navbar_urls)]

    section.content = {'navbar_items': navbar_items}
    return section

@app.route('/edit_public_navbar_style/<int:website_id>', methods=['POST'])
@login_required
def edit_public_navbar_style(website_id):
    website = Website.query.get_or_404(website_id)

    if website.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403

    data = request.get_json() or {}

    try:
        margin = int(data.get('margin') or 0)
    except ValueError:
        margin = 0

    margin = max(0, min(80, margin))

    website.public_navbar_style = {
        'title': data.get('title', website.name),
        'icon_url': data.get('icon_url', ''),
        'background': data.get('background', 'rgba(20,20,20,0.9)'),
        'text_color': data.get('text_color', '#ffffff'),
        'opacity': data.get('opacity', 0.9),
        'blur': data.get('blur', 14),
        'border_radius': data.get('border_radius', 0),
        'shadow': data.get('shadow', True),
        'sticky': data.get('sticky', True),
        'title_alignment': data.get('title_alignment', 'left'),
        'margin': margin
    }
    db.session.commit()

    return jsonify({'success': True})

@app.route('/upload_public_navbar_icon/<int:website_id>', methods=['POST'])
@login_required
def upload_public_navbar_icon(website_id):
    website = Website.query.get_or_404(website_id)

    if website.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403

    if 'icon' not in request.files:
        return jsonify({'success': False, 'message': 'No icon file uploaded'}), 400

    file = request.files['icon']

    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    if not (
            file.filename.lower().endswith('.svg') or
            file.filename.lower().endswith('.png')
    ):
        return jsonify({'success': False, 'message': 'Only SVG and PNG files are allowed'}), 400

    extension = file.filename.rsplit('.', 1)[1].lower()


    user_icon_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id), 'navbar')
    os.makedirs(user_icon_folder, exist_ok=True)

    filename = f'public-icon.{extension}'
    filepath = os.path.join(user_icon_folder, filename)

    for old_filename in ['public-icon.svg', 'public-icon.png']:
        old_path = os.path.join(user_icon_folder, old_filename)
        if os.path.exists(old_path):
            os.remove(old_path)

    file.save(filepath)

    icon_url = url_for(
        'static',
        filename=f'uploads/{current_user.id}/navbar/{filename}'
    )

    style = website.public_navbar_style or {}
    style['icon_url'] = icon_url
    website.public_navbar_style = style

    db.session.commit()

    return jsonify({
        'success': True,
        'icon_url': icon_url
    })

@app.route('/update_section', methods=['POST'])
@login_required
def update_section():
    section_id = request.form.get('section_id')
    section_type = request.form.get('section_type')

    # Debug logging to see what data is being received
    print(f"Received section_id: {section_id}, section_type: {section_type}")
    print(f"Form data: {request.form}")

    section = PageSection.query.get(section_id)
    if section is None:
        return jsonify({'status': 'error', 'message': 'Failed to update section'})

    form_data = request.form

    if section_type == 'map':
        section = update_map_section(section, form_data)
    # elif section_type == 'code':
    #     section = update_code_section(section, form_data)
    elif section_type == 'images':
        section = update_images_section(section, form_data)
    elif section_type == 'text':
        section = update_text_section(section, form_data)
    elif section_type == 'button':
        section = update_button_section(section, form_data)
    elif section_type == 'contact_form':
    #     section = update_contact_section(section, form_data)
    # elif section_type == 'header':
        section = update_header_section(section, form_data)
    elif section_type == 'youtube_video':
        section = update_youtube_video_section(section, form_data)
    # elif section_type == 'navbar':
    #     section = update_navbar_section(section, form_data)
    else:
        return jsonify({'status': 'error', 'message': 'Unknown section type'})

    db.session.commit()
    return jsonify({'status': 'success', 'message': f'{section_type} section updated'})


@app.route('/toggle_public_page', methods=['POST'])
@login_required
def toggle_public_page():
    data = request.json
    site_active_status = data.get('site_active_status')
    website_id = data.get('website_id')
    page_id = data.get('page_id')  # Get the page_id from the request data
    print("Publish WEBSITE ID: ", website_id, " PAGE ID: ", page_id)

    # Verify the user owns the website
    website = Website.query.filter_by(id=website_id, user_id=current_user.id).first()

    if not website:
        return jsonify({'status': 'error', 'message': 'Unauthorized or invalid website ID'})

    # Update the site active status for the specific page
    content = PublicPageContent.query.filter_by(website_id=website_id, id=page_id).first()
    if content:
        content.site_active_status = site_active_status
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Public page status updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update public page status'})


@app.route('/remove_images_from_section', methods=['POST'])
@login_required
def remove_images_from_section():
    data = request.json
    section_id = data.get('sectionId')
    link_ids = data.get('linkIds')  # These are SectionImage IDs

    if not link_ids:
        return jsonify({'status': 'error', 'message': 'No images selected'})

    # Delete the links, not the pictures
    SectionImage.query.filter(
        SectionImage.id.in_(link_ids),
        SectionImage.section_id == section_id
    ).delete(synchronize_session=False)

    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Images removed from section'})


def update_image_order(order_list):
    try:
        # order_list expected format: [{'link_id': 12, 'order': 1, 'sectionId': 5}, ...]
        for item in order_list:
            link_id = item.get('link_id')
            new_order = item.get('order')
            new_section_id = item.get('sectionId')

            # Query the SectionImage (the link), not the Picture itself
            link = db.session.get(SectionImage, link_id)

            if not link:
                # Fallback: if link_id isn't provided, try to find it via picture_id and section_id
                # (This helps if your JS is still sending 'id' instead of 'link_id')
                picture_id = item.get('id')
                link = SectionImage.query.filter_by(
                    picture_id=picture_id,
                    section_id=new_section_id
                ).first()

            if link:
                print(f"Moving link {link.id}: Section {link.section_id} -> {new_section_id}, Order -> {new_order}")
                link.order = new_order
                link.section_id = new_section_id
            else:
                print(f"Link not found for item: {item}")
                continue

        db.session.commit()
        return {'status': 'success', 'message': 'Image order and sections updated'}

    except Exception as e:
        db.session.rollback()
        print(f"Error updating image order: {str(e)}")
        return {'status': 'error', 'message': str(e)}


@app.route('/update_image_order', methods=['POST'])
@login_required
def update_image_order_route():
    # if not session.get('logged_in'):
    #     return jsonify({'status': 'error', 'message': 'Unauthorized'})

    # current_user is guaranteed to exist and be logged in
    user_id = current_user.id  # or .get_id() depending on your User model

    print(f"Logged in as user {user_id}")

    order_list = request.json

    if not isinstance(order_list, list) or not all(isinstance(order, dict) for order in order_list):
        return jsonify({'status': 'error', 'message': 'Invalid request format'})

    result = update_image_order(order_list)
    return jsonify(result)


@app.route('/delete_selected_images', methods=['POST'])
@login_required
def delete_selected_images():
    try:
        data = request.json
        section_id = data.get('sectionId')
        image_ids = data.get('imageIds')

        # Delete the images associated with the given image IDs and section ID
        for image_id in image_ids:
            picture = Picture.query.filter_by(id=image_id, section_id=section_id).first()
            if picture:
                db.session.delete(picture)

        # Commit the changes to the database
        db.session.commit()

        return {'status': 'success', 'message': 'Selected images deleted successfully'}
    except Exception as e:
        db.session.rollback()
        error_message = str(e)
        return {'status': 'error', 'message': error_message}


@app.route('/move_image_to_section', methods=['POST'])
@login_required
def move_image_to_section():
    data = request.json

    if not data or 'sourceLinkId' not in data or 'sourceSection' not in data or 'targetSection' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid request format'})

    source_link_id = data['sourceLinkId']
    source_section_id = int(data['sourceSection'])
    target_section_id = int(data['targetSection'])

    try:
        link = db.session.get(SectionImage, source_link_id)

        if not link:
            return jsonify({'status': 'error', 'message': 'SectionImage link not found'})

        if link.section_id != source_section_id:
            return jsonify({'status': 'error', 'message': 'Source section mismatch'})

        # Move link to new section
        link.section_id = target_section_id

        db.session.flush()

        # Re-number source section
        source_links = SectionImage.query.filter_by(section_id=source_section_id).order_by(SectionImage.order).all()
        for index, item in enumerate(source_links, start=1):
            item.order = index

        # Put moved image at end of target section
        target_links = SectionImage.query.filter_by(section_id=target_section_id).order_by(SectionImage.order).all()
        for index, item in enumerate(target_links, start=1):
            item.order = index

        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Image moved successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/calendar/events/<int:section_id>.ics')
def download_calendar_events(section_id):
    # Fetch events from the database based on the provided section_id
    events = CalendarEvent.query.filter_by(section_id=section_id).all()

    # Check if events exist for the provided section_id
    if not events:
        return Response(status=404)

    # Generate iCal feed for the specified section
    cal = Calendar()
    cal.add('prodid', '-//My Calendar//example.com//')
    cal.add('version', '2.0')

    for event in events:
        event_obj = Event()
        event_obj.add('summary', event.title)
        event_obj.add('dtstart', event.start)
        event_obj.add('dtend', event.end)
        cal.add_component(event_obj)

    # Return the iCal feed as a response
    return Response(cal.to_ical(), mimetype='text/calendar')


@app.route('/page/<int:section_id>/add_event', methods=['POST'])
@login_required
def add_event(section_id):
    try:
        data = request.get_json()

        title = data.get('title')
        description = data.get('description')
        start_str = data.get('start')
        end_str = data.get('end')
        background_color = data.get('backgroundColor')

        local_timezone = pytz.timezone('America/Chicago')

        start = parser.parse(str(start_str))
        end = parser.parse(str(end_str)) if end_str else None

        if start.tzinfo is None:
            start = local_timezone.localize(start)
        else:
            start = start.astimezone(local_timezone)

        if end:
            if end.tzinfo is None:
                end = local_timezone.localize(end)
            else:
                end = end.astimezone(local_timezone)

        event = CalendarEvent(
            title=title,
            description=description,
            start=start,
            end=end,
            background_color=background_color,
            section_id=section_id
        )

        db.session.add(event)
        db.session.commit()

        return jsonify({
            'message': 'Event added successfully',
            'event': event.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/page/<int:section_id>/events', methods=['GET'])
def get_events(section_id):
    events = CalendarEvent.query.filter_by(section_id=section_id).all()
    return jsonify([event.to_dict() for event in events])


@app.route('/page/<int:section_id>/update_event', methods=['POST'])
@login_required
def update_event(section_id):
    try:
        data = request.get_json()
        event_id = data.get('id')

        if not event_id:
            return jsonify({'message': 'Event id is required'}), 400

        event = CalendarEvent.query.filter_by(id=event_id, section_id=section_id).first()
        if not event:
            return jsonify({'message': 'Event not found'}), 404

        local_timezone = pytz.timezone('America/Chicago')

        start = parser.parse(str(data.get('start'))) if data.get('start') else None
        end = parser.parse(str(data.get('end'))) if data.get('end') else None

        if start:
            if start.tzinfo is None:
                start = local_timezone.localize(start)
            else:
                start = start.astimezone(local_timezone)

        if end:
            if end.tzinfo is None:
                end = local_timezone.localize(end)
            else:
                end = end.astimezone(local_timezone)

        event.title = data.get('title', event.title)
        event.description = data.get('description', event.description)
        event.start = start or event.start
        event.end = end
        event.background_color = data.get('backgroundColor', event.background_color)

        db.session.commit()
        return jsonify({
            'message': 'Event updated successfully',
            'event': event.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/page/<int:section_id>/delete_event', methods=['POST'])
@login_required
def delete_event(section_id):
    try:
        data = request.get_json()
        event_id = data.get('id')

        if not event_id:
            return jsonify({'message': 'Event id is required'}), 400

        event = CalendarEvent.query.filter_by(id=event_id, section_id=section_id).first()
        if event:
            db.session.delete(event)
            db.session.commit()
            return jsonify({'message': 'Event deleted successfully'}), 200

        return jsonify({'message': 'Event not found'}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/saved_colors', methods=['GET'])
@login_required
def get_saved_colors():
    colors = SavedColor.query.filter_by(user_id=current_user.id).order_by(SavedColor.created_at.desc()).all()
    return jsonify({'colors': [c.color for c in colors]})

@app.route('/saved_colors', methods=['POST'])
@login_required
def save_color():
    data = request.get_json()
    color = data.get('color')

    if not color:
        return jsonify({'success': False, 'error': 'Missing color'}), 400

    exists = SavedColor.query.filter_by(user_id=current_user.id, color=color).first()
    if not exists:
        db.session.add(SavedColor(user_id=current_user.id, color=color))
        db.session.commit()

    return jsonify({'success': True})

@app.route('/saved_colors', methods=['DELETE'])
@login_required
def delete_saved_color():
    data = request.get_json()
    color = data.get('color')

    SavedColor.query.filter_by(user_id=current_user.id, color=color).delete()
    db.session.commit()

    return jsonify({'success': True})


if __name__ == '__main__':
    # Run migrations
    # run_migrations()

    # Create all tables
    with app.app_context():
        db.create_all()

        # Check if any PublicPageContent objects exist
        # existing_public_page_content = PublicPageContent.query.first()

        # # If no PublicPageContent objects exist, create and initialize one
        # if existing_public_page_content is None:
        #     public_page_content = PublicPageContent(site_active_status=True)
        #
        #     # Add header section
        #     header_section_content = {'header_text': 'Default Header Text'}
        #     header_section = PageSection(
        #         section_type='header',
        #         order=1,
        #         content=header_section_content,
        #         page_content=public_page_content
        #     )
        #     db.session.add(header_section)
        #
        #     db.session.add(public_page_content)
        #     db.session.commit()
        #     print("PublicPageContent initialized successfully with header section.")
        # else:
        #     print("PublicPageContent already exists. No initialization needed.")

    # Get the port from the environment variable or default to 5000
    port = int(os.environ.get('PORT', 5772))
    app.run(debug=False, host='0.0.0.0', port=port)
