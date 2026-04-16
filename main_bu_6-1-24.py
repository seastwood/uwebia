import logging
import shutil
import subprocess
import os
from calendar import Calendar

import pytz
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory, Response
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from dateutil import parser
from icalendar import Calendar, Event


logging.basicConfig(level=logging.DEBUG)
from operator import itemgetter

# # Set the static folder path
# static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Static')
#
# # Set the template folder path
# template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates')

# Set the static folder path
# static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Static')


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

# Configure Flask-Mail
app.config['MAIL_SERVER'] = '24.118.2.29'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'code@nodaro.com'
app.config['MAIL_PASSWORD'] = '2857'
app.config['MAIL_DEFAULT_SENDER'] = 'uwebia-inquiry@nodaro.com'

db = SQLAlchemy(app)
mail = Mail(app)
migrate = Migrate(app, db)  # Add this line to initialize Flask-Migrate


# Run Flask-Migrate commands to initialize and apply migrations
def run_migrations():
    migrate_command = ['flask', '--app', 'main', 'db', 'migrate', '-m', 'Migration maintenance.']
    upgrade_command = ['flask', '--app', 'main', 'db', 'upgrade']

    subprocess.run(migrate_command, cwd=os.path.dirname(__file__), check=True)
    subprocess.run(upgrade_command, cwd=os.path.dirname(__file__), check=True)


# Define the model for storing public page content
# class PublicPageContent(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     all_pictures = db.relationship('Picture', backref='page_content', lazy=True)  # Relationship for all pictures
#
#     header_text = db.Column(db.String)  # New attribute for header text
#
#     button_link = db.Column(db.String)  # New attribute for button link
#     button_text = db.Column(db.String)  # New attribute for button text
#     button_enabled = db.Column(db.Boolean, default=False)
#
#     text = db.Column(db.String)
#
#     status = db.Column(db.Boolean, default=False)
#
#     latitude = db.Column(db.Float)  # New attribute for latitude
#     longitude = db.Column(db.Float)  # New attribute for longitude
#     map_enabled = db.Column(db.Boolean, default=False)  # New attribute for map toggle status
#     map_marker_label = db.Column(db.String)
#
#     contact_form_title = db.Column(db.String)
#     contact_email = db.Column(db.String)
#     contact_form_enabled = db.Column(db.Boolean, default=False)
#
#     sections = db.relationship('PageSection', backref='page_content', lazy=True, cascade="all, delete-orphan")
#
#     def __repr__(self):
#         return f"<PublicPageContent {self.id}>"

class PublicPageContent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    all_pictures = db.relationship('Picture', backref='page_content', lazy=True)  # Relationship for all pictures
    sections = db.relationship('PageSection', backref='page_content', lazy=True, cascade="all, delete-orphan")
    site_active_status = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<PublicPageContent {self.id}>"


class PageSection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section_type = db.Column(db.String, nullable=False)
    order = db.Column(db.Integer)
    content = db.Column(db.JSON)
    page_content_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'page_content_id': self.page_content_id,
            'order': self.order,
            'section_type': self.section_type,
            'content': self.content
        }

    def __repr__(self):
        return f"<PageSection {self.id} - {self.section_type}>"


class Picture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(1000))
    order = db.Column(db.Integer)
    page_content_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'))
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id', name='fk_picture_section_id'))

    def __repr__(self):
        return f"<Picture {self.id}>"


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


# Hardcoded admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin')

# Set the upload folder path
UPLOAD_FOLDER = os.path.join(static_folder, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



# Route to handle sending email
@app.route('/send_email', methods=['POST'])
def send_email():
    # Get form data
    sender_email = request.form['senders_email']
    subject = request.form['message_subject']
    body = request.form['message_body']

    # Get the contact email from the database
    contact_content = PublicPageContent.query.first()
    if contact_content is None:
        return jsonify({'status': 'error', 'message': 'No contact email found'})
    # Construct the email body with the sender's email included
    formatted_body = f"""
    You have received a new message from your uwebia website contact form.

    Here are the details:

    Sender Email: {sender_email}
    Subject: {subject}
    Message Body:
    {body}
    """

    recipient_email = contact_content.contact_email

    # Create message
    message = Message(subject=subject,
                      # sender=sender_email,
                      recipients=[recipient_email],
                      body=formatted_body)

    # Send email
    try:
        mail.send(message)
        return jsonify({'status': 'success', 'message': 'Email sent successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to send email: {str(e)}'})


# Route for the login page with API key check
@app.route('/admin/login/<api_key>')
def login_page(api_key):
    if api_key != ADMIN_API_KEY:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    return render_template('login.html')


# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['logged_in'] = True
        return redirect(url_for('admin_page', api_key=ADMIN_API_KEY))
    else:
        return jsonify({'status': 'error', 'message': 'Invalid username or password'})


# Route for the admin page with API key check
@app.route('/admin/<api_key>')
def admin_page(api_key):
    if api_key != ADMIN_API_KEY:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})

    if not session.get('logged_in'):
        return redirect(url_for('login_page', api_key=ADMIN_API_KEY))

    # Fetch the content from the database
    content = PublicPageContent.query.first()
    page_id = content.id
    if content is None:
        # initial_content = get_initial_content()
        # Initialize the database content if it doesn't exist
        public_content = PublicPageContent()
        db.session.add(public_content)
        db.session.commit()
        site_active_status = False
        sections = []
    else:
        site_active_status = content.site_active_status
        # Fetch sections ordered by PageSection.order
        sections = PageSection.query.filter_by(page_content_id=content.id).order_by(PageSection.order).all()

    return render_template('admin.html',
                           site_active_status=site_active_status,
                           sections=sections,
                           page_id=page_id)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


from flask import jsonify


# Assuming you have a Flask app instance named 'app'
@app.route('/get_sections', methods=['GET'])
def get_sections():
    # Query all PageSection objects and sort them by order number
    sections = PageSection.query.order_by(PageSection.order).all()

    # Convert each PageSection object to a dictionary
    sections_data = [section.to_dict() for section in sections]
    print("get sections data: ", sections_data)

    # Return the sections data as JSON
    return jsonify(sections_data)  # Directly return the list of sections


@app.route('/page/<int:page_id>/add_section', methods=['POST'])
def add_section(page_id):
    data = request.json
    # Get the maximum order number of existing sections for the given page
    max_order = PageSection.query.filter_by(page_content_id=page_id).order_by(PageSection.order.desc()).first()
    if max_order:
        new_order = max_order.order + 1
    else:
        new_order = 1

    section_content = data['content']

    section = PageSection(
        section_type=data['section_type'],
        order=new_order,
        content=section_content,
        page_content_id=page_id
    )
    db.session.add(section)
    db.session.commit()
    return jsonify({'message': 'Section added successfully'}), 201


@app.route('/page/<int:page_id>/remove_section/<int:section_id>', methods=['DELETE'])
def remove_section(page_id, section_id):
    section = PageSection.query.get_or_404(section_id)
    # Get the order of the section to be removed
    removed_order = section.order
    db.session.delete(section)
    db.session.commit()

    # Update the order numbers of remaining sections with order greater than the removed section
    remaining_sections = PageSection.query.filter(PageSection.page_content_id == page_id,
                                                  PageSection.order > removed_order).all()
    for s in remaining_sections:
        s.order -= 1

    db.session.commit()
    return jsonify({'message': 'Section removed successfully'}), 200


@app.route('/page/<int:page_id>/reorder_sections', methods=['POST'])
def reorder_sections(page_id):
    data = request.json
    for item in data['sections']:
        section = PageSection.query.get(item['id'])
        section.order = item['order']
    db.session.commit()
    return jsonify({'message': 'Sections reordered successfully'}), 200


# Route to handle updating section order
@app.route('/update_section_order', methods=['POST'])
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


@app.route('/update_public_images', methods=['POST'])
def update_public_images():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    if 'picture' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part'})

    files = request.files.getlist('picture')
    section_id = request.form.get('section_id')  # Get the section ID from the form
    print("Image uploaded to section:", section_id)

    if not section_id:
        return jsonify({'status': 'error', 'message': 'Section ID is missing'})

    picture_urls = []  # Store picture URLs

    # Get the maximum order value within the section
    max_order = db.session.query(func.max(Picture.order)).filter_by(section_id=section_id).scalar() or 0

    for file in files:
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file'})

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(uploads_folder, filename)
            file.save(filepath)
            picture_url = url_for('static', filename='uploads/' + filename)

            max_order += 1  # Increment the max_order for each new picture
            picture = Picture(url=picture_url, order=max_order, section_id=section_id)  # Associate with section
            db.session.add(picture)
            db.session.commit()
            picture_urls.append(picture_url)
        else:
            return jsonify({'status': 'error', 'message': 'Invalid file format'})

    return jsonify({'status': 'success', 'message': 'Images uploaded successfully', 'section_id': section_id})


@app.route('/get_uploaded_images')
def get_uploaded_images():
    section_id = request.args.get('section_id')
    if not section_id:
        return jsonify({'status': 'error', 'message': 'Section ID is missing'})

    pictures = Picture.query.filter_by(section_id=section_id).order_by(Picture.order).all()
    images_data = [{'id': picture.id, 'url': picture.url, 'order': picture.order} for picture in pictures]

    return jsonify({'images': images_data})


@app.route('/update_public_text', methods=['POST'])
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


@app.route('/update_map_marker', methods=['POST'])
def update_map_marker():
    data = request.form
    latitude = data.get('latitude', type=float)
    longitude = data.get('longitude', type=float)
    map_enabled = data.get('map_enabled') == 'on'
    map_marker_label = data.get('map_marker_label')

    # Assuming there is only one PublicPageContent entry, or you need to specify which one to update
    page_content = PublicPageContent.query.first()
    if page_content:
        page_content.latitude = latitude
        page_content.longitude = longitude
        page_content.map_enabled = map_enabled
        page_content.map_marker_label = map_marker_label
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Map marker updated successfully'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Page content not found'}), 404


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


@app.route('/static/<path:filename>')
def serve_static(filename):
    print("Request for static file:", filename)
    return send_from_directory(app.static_folder, filename)


@app.route('/')
def public_page():
    content = PublicPageContent.query.first()

    if content is None:
        return jsonify({'status': 'error', 'message': 'Public page content not found'})

    if not content.site_active_status:
        return jsonify({'status': 'error', 'message': 'Public page is currently inactive'})

    sections = PageSection.query.filter_by(page_content_id=content.id).order_by(PageSection.order).all()

    pictures_by_section = {}
    for section in sections:
        section_pictures = Picture.query.filter_by(section_id=section.id).order_by(Picture.order).all()
        pictures_by_section[section.id] = [picture.url for picture in section_pictures]

    sections_dict = [section.to_dict() for section in sections]

    public_page_content = {
        'page_id': content.id,
        'sections': sections_dict,
        'pictures_by_section': pictures_by_section
    }

    print("Sections Data:", sections_dict)
    print("Pictures by Section:", pictures_by_section)

    return render_template('public.html', content=public_page_content)


def update_map_section(section, form_data):
    latitude = form_data.get('latitude')
    longitude = form_data.get('longitude')
    map_marker_label = form_data.get('map_marker_label')
    map_enabled = form_data.get('map_enabled') == 'on'

    section.content = {
        'latitude': latitude,
        'longitude': longitude,
        'marker_label': map_marker_label,
        'enabled': map_enabled
    }
    return section


def update_text_section(section, form_data):
    text_content = form_data.get('text')
    section.content = {'text': text_content}
    return section


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


@app.route('/update_section', methods=['POST'])
def update_section():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

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
    elif section_type == 'text':
        section = update_text_section(section, form_data)
    elif section_type == 'button':
        section = update_button_section(section, form_data)
    elif section_type == 'contact_form':
        section = update_contact_section(section, form_data)
    elif section_type == 'header':
        section = update_header_section(section, form_data)
    elif section_type == 'youtube_video':
        section = update_youtube_video_section(section, form_data)
    else:
        return jsonify({'status': 'error', 'message': 'Unknown section type'})

    db.session.commit()
    return jsonify({'status': 'success', 'message': f'{section_type} section updated'})


# Route to handle toggling the public page status
@app.route('/toggle_public_page', methods=['POST'])
def toggle_public_page():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    site_active_status = request.json.get('site_active_status')

    # Update the status in the database
    content = PublicPageContent.query.first()
    if content is not None:
        content.site_active_status = site_active_status
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Public page status updated'})
    else:
        return jsonify({'status': 'error', 'message': 'Failed to update public page status'})


def update_image_order(order_list):
    try:
        # Update the order of images in the database
        for order in order_list:
            picture_id = order.get('id')
            new_order = order.get('order')
            section_id = order.get('sectionId')  # Get the section ID

            # Check if the picture exists
            picture = Picture.query.get(picture_id)
            if not picture:
                return {'status': 'error', 'message': f'Picture with ID {picture_id} does not exist'}

            # Check if the section exists
            section = PageSection.query.get(section_id)
            if not section:
                return {'status': 'error', 'message': f'Section with ID {section_id} does not exist'}

            # Update the picture's order and section ID
            print(f"Updating order for picture {picture_id} to {new_order} in section {section_id}")  # Debug statement
            picture.order = new_order
            picture.section_id = section_id

        # Commit the changes to the database
        db.session.commit()
        return {'status': 'success', 'message': 'Image order updated'}
    except Exception as e:
        db.session.rollback()
        print(f"Error updating image order: {str(e)}")  # Debug statement
        return {'status': 'error', 'message': str(e)}


@app.route('/update_image_order', methods=['POST'])
def update_image_order_route():
    if not session.get('logged_in'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'})

    order_list = request.json

    if not isinstance(order_list, list) or not all(isinstance(order, dict) for order in order_list):
        return jsonify({'status': 'error', 'message': 'Invalid request format'})

    result = update_image_order(order_list)
    return jsonify(result)


@app.route('/delete_selected_images', methods=['POST'])
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


@app.route('/delete_image', methods=['POST'])
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


@app.route('/move_image_to_section', methods=['POST'])
def move_image_to_section():
    data = request.json

    if not data or 'sourceOrder' not in data or 'sourceSection' not in data or 'targetSection' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid request format'})

    source_order = data['sourceOrder']
    source_section_id = data['sourceSection']
    target_section_id = data['targetSection']

    try:
        # Find the picture to be moved
        picture = Picture.query.filter_by(order=source_order, section_id=source_section_id).first()

        if picture:
            # Update the section ID of the picture
            picture.section_id = target_section_id

            # Get all pictures in the source section and update their orders
            source_section_pictures = Picture.query.filter_by(section_id=source_section_id).order_by(
                Picture.order).all()
            for index, pic in enumerate(source_section_pictures, start=1):
                pic.order = index

            # Get all pictures in the target section and update their orders
            target_section_pictures = Picture.query.filter_by(section_id=target_section_id).order_by(
                Picture.order).all()
            for index, pic in enumerate(target_section_pictures, start=len(source_section_pictures) + 1):
                pic.order = index

            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Image moved successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Image not found'})
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
def add_event(section_id):
    try:
        data = request.json
        title = data.get('title')
        description = data.get('description')
        start_str = data.get('start')
        end_str = data.get('end')
        background_color = data.get('backgroundColor')

        # Set the local time zone to Central Standard Time (CST)
        local_timezone = pytz.timezone('America/Chicago')

        # Parse datetime strings and convert to local timezone
        start = parser.parse(str(start_str)).astimezone(local_timezone)
        end = parser.parse(str(end_str)).astimezone(local_timezone)


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
        return jsonify({'message': 'Event added successfully'}), 201
    except KeyError as e:
        return jsonify({'error': f'Missing key in request data: {e}'}), 400
    except ValueError as e:
        return jsonify({'error': f'Invalid date format: {e}'}), 400
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500


@app.route('/page/<int:section_id>/events', methods=['GET'])
def get_events(section_id):
    events = CalendarEvent.query.filter_by(section_id=section_id).all()
    return jsonify([event.to_dict() for event in events])


@app.route('/page/<int:section_id>/update_event', methods=['POST'])
def update_event(section_id):
    data = request.json
    event = CalendarEvent.query.get(data['id'])
    if event:
        event.title = data['title']
        event.start = data['start']
        event.end = data['end']
        db.session.commit()
        return jsonify({'message': 'Event updated successfully'}), 200
    return jsonify({'message': 'Event not found'}), 404


@app.route('/page/<int:section_id>/delete_event', methods=['POST'])
def delete_event(section_id):
    data = request.json
    event = CalendarEvent.query.get(data['id'])
    if event:
        db.session.delete(event)
        db.session.commit()
        return jsonify({'message': 'Event deleted successfully'}), 200
    return jsonify({'message': 'Event not found'}), 404


if __name__ == '__main__':
    # Run migrations
    run_migrations()

    # Create all tables
    with app.app_context():
        db.create_all()

        # Check if any PublicPageContent objects exist
        existing_public_page_content = PublicPageContent.query.first()

        # If no PublicPageContent objects exist, create and initialize one
        if existing_public_page_content is None:
            public_page_content = PublicPageContent(site_active_status=True)

            # Add header section
            header_section_content = {'header_text': 'Default Header Text'}
            header_section = PageSection(
                section_type='header',
                order=1,
                content=header_section_content,
                page_content=public_page_content
            )
            db.session.add(header_section)

            db.session.add(public_page_content)
            db.session.commit()
            print("PublicPageContent initialized successfully with header section.")
        else:
            print("PublicPageContent already exists. No initialization needed.")

    # Get the port from the environment variable or default to 5000
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
