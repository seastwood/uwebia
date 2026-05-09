import io
import logging
import os
import random
import shutil
import zipfile
import smtplib
import subprocess
import ssl
import uuid
import copy
import re
import ipaddress
import secrets
import hashlib
import json
import mimetypes
import time
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from PIL import Image, ImageOps
import pytz
from dateutil import parser
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory, Response, \
    flash, make_response
from flask_login import LoginManager, login_user, logout_user, login_required
from flask_login import current_user, UserMixin
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from icalendar import Calendar as ICalendar, Event as ICalEvent
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from sqlalchemy import func, or_
from sqlalchemy.orm import validates
from trio._tools.mypy_annotate import export
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask import send_file

from bs4 import BeautifulSoup

logging.basicConfig(level=logging.DEBUG)

# Set the template folder path
template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Templates')

# Set admin page API key
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'default_api_key')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
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

from sqlalchemy import event as _sa_event


def _set_sqlite_pragmas(dbapi_conn, _rec):
    """Applied to every new SQLite connection for concurrency hardening."""
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")  # readers never block writers
    cur.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, much faster
    cur.execute("PRAGMA foreign_keys=ON")  # enforce FK constraints
    cur.execute("PRAGMA busy_timeout=5000")  # wait up to 5 s on locked DB
    cur.close()


login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)  # Add this line to initialize Flask-Migrate

# ── API key encryption ────────────────────────────────────────────────────────
# Keys are encrypted with Fernet (AES-128-CBC + HMAC) before being stored.
# The encryption key is derived from app.secret_key so it never touches the DB.
from cryptography.fernet import Fernet, InvalidToken
import base64, hashlib as _hashlib


def _get_fernet():
    raw = app.secret_key
    if isinstance(raw, str):
        raw = raw.encode()
    derived = _hashlib.sha256(raw).digest()  # 32 bytes
    fernet_key = base64.urlsafe_b64encode(derived)  # Fernet needs URL-safe b64
    return Fernet(fernet_key)


def encrypt_api_key(plaintext: str) -> str:
    if not plaintext:
        return ''
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_api_key(ciphertext: str) -> str:
    if not ciphertext:
        return ''
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        # Graceful fallback: treat as plain-text (keys stored before this change)
        return ciphertext


# ─────────────────────────────────────────────────────────────────────────────

MAX_UPLOAD_MB = 10
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

PUBLIC_MAX_WIDTH = 1600
THUMB_SIZE = (500, 500)
PUBLIC_QUALITY = 82
THUMB_QUALITY = 75

EMERGENCY_LOGIN_TOKENS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'instance',
    'emergency_login_tokens.json'
)

SECURITY_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'config',
    'security.json'
)

DEFAULT_SECURITY_CONFIG = {
    "allow_emergency_login": False,
    "emergency_login_expiration_minutes": 10
}

SERVER_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'config',
    'server.json'
)

DEFAULT_SERVER_CONFIG = {
    "host": "0.0.0.0",
    "port": 5772,
    "debug": False
}


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class PermissionGroup(db.Model):
    """A named set of permissions that can be shared across many sub-admin users.
    Editing the group instantly updates every member's effective permissions."""
    __tablename__ = 'permission_group'

    id = db.Column(db.Integer, primary_key=True)
    owner_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    permissions = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship(
        'User',
        foreign_keys='User.permission_group_id',
        backref=db.backref('permission_group', lazy='select'),
        lazy=True,
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description or '',
            'permissions': self.permissions or {},
            'member_count': len(self.members),
        }


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    # Sub-admin support: if set, this user belongs to the parent admin
    parent_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    permission_group_id = db.Column(db.Integer, db.ForeignKey('permission_group.id'), nullable=True)
    permissions = db.Column(db.JSON, nullable=True)  # dict of 'section.action': bool

    two_factor_enabled = db.Column(db.Boolean, nullable=False, default=False)
    two_factor_email = db.Column(db.String(255), nullable=True)
    two_factor_activated_at = db.Column(db.DateTime, nullable=True)
    two_factor_last_email_settings_version = db.Column(db.String(64), nullable=True)
    two_factor_disabled_reason = db.Column(db.String(255), nullable=True)
    two_factor_disabled_at = db.Column(db.DateTime, nullable=True)
    two_factor_last_sent_at = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_seen_at  = db.Column(db.DateTime, nullable=True)
    two_factor_needs_attention = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )
    admin_url_key = db.Column(db.String(120), nullable=True)
    admin_url_key_enabled = db.Column(db.Boolean, nullable=False, default=False)

    timezone = db.Column(db.String(100), nullable=False, default='America/Chicago')
    date_format = db.Column(db.String(50), nullable=False, default='%b %d, %Y %I:%M %p')

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

    @property
    def is_sub_admin(self):
        return self.parent_user_id is not None

    @property
    def root_user_id(self):
        """The owning admin's user ID (self for main admins, parent for sub-admins)."""
        return self.parent_user_id or self.id

    def has_permission(self, key):
        """Main admins always have all permissions. Sub-admins check their group (if any), then individual permissions."""
        if not self.is_sub_admin:
            return True
        if self.permission_group_id and self.permission_group:
            return bool((self.permission_group.permissions or {}).get(key, False))
        return bool((self.permissions or {}).get(key, False))

    def __repr__(self):
        return f"<User {self.username}>"


def _perm_label(key):
    """Return a human-readable label for a permission key like 'pages.edit'."""
    section, _, action = key.partition('.')
    section_labels = {
        'pages': 'Pages', 'sections': 'Sections', 'appearance': 'Appearance',
        'code': 'Code', 'assets': 'Asset Library', 'calendars': 'Calendars',
        'ai_agents': 'AI Agents', 'forum': 'Forum', 'comments': 'Comments',
        'messages': 'Messages', 'settings': 'Settings', 'templates': 'Templates',
        'admin_users': 'Admin Users',
    }
    action_labels = {
        'view': 'view', 'edit': 'edit', 'create': 'create', 'delete': 'delete',
        'publish': 'publish', 'upload': 'upload', 'folders': 'manage folders',
        'ai_generate': 'generate with AI', 'groups': 'manage groups',
        'templates': 'use templates', 'navbar': 'edit navbar',
        'page_code': 'use page code editor', 'sections': 'edit code sections',
        'tweaks': 'use code tweaks', 'ai': 'use AI assistance',
        'events': 'manage events', 'subscriptions': 'manage subscriptions',
        'chat': 'chat with agents', 'use': 'use agents',
        'settings': 'edit settings', 'moderate': 'moderate content',
        'manage_users': 'manage users', 'delete_posts': 'delete posts',
        'download': 'download files',
    }
    s = section_labels.get(section, section.replace('_', ' ').title())
    a = action_labels.get(action, action.replace('_', ' '))
    return f'{s} › {a}'


# Permissions covered by website.draft.edit (content editing inside a draft).
# Deliberately excludes: code.ai (always requires explicit grant),
# and pages.create/delete/templates (controlled by website.draft.pages instead).
_DRAFT_EDIT_COVERS = frozenset({
    'pages.edit', 'pages.publish', 'pages.details', 'pages.reorder',
    'sections.edit', 'sections.create', 'sections.delete', 'sections.reorder',
    'sections.groups', 'sections.templates',
    'appearance.background', 'appearance.navbar', 'appearance.colors', 'appearance.page_code',
    'code.sections', 'code.tweaks',
    'calendars.view', 'calendars.create', 'calendars.edit',
    'calendars.delete', 'calendars.events', 'calendars.subscriptions',
    'website.edit',
})

# Permissions covered by website.draft.pages (creating / deleting pages in a draft).
# Kept separate so admins can give someone edit access without page management.
_DRAFT_PAGES_COVERS = frozenset({
    'pages.create', 'pages.delete', 'pages.templates',
})


def _is_draft_context():
    """Return True when the current request is operating on a draft website.
    Resolves the website via URL path args (website_id, page_id, section_id,
    group_id, row_id) then falls back to common form/JSON body keys.
    Result is cached in flask.g so multiple require_perm calls in the same
    request only do a single round of DB lookups."""
    from flask import g
    if hasattr(g, '_draft_ctx'):
        return g._draft_ctx

    def _int(key):
        for source in (
                request.view_args or {},  # URL path params  e.g. /section/<id>
                request.args,  # query-string     e.g. ?section_id=5
                request.form,  # form body
        ):
            v = source.get(key)
            if v is not None:
                try:
                    return int(v)
                except:
                    pass
        try:
            if request.is_json:
                data = request.get_json(silent=True) or {}
                v = data.get(key)
                if v is not None:
                    return int(v)
        except Exception:
            pass
        return None

    result = False
    try:
        wid = _int('website_id')
        pid = _int('page_id') or _int('page_content_id')
        # Some routes use first_section_id / second_section_id (swap endpoint)
        sid = (_int('section_id')
               or _int('first_section_id')
               or _int('second_section_id'))
        gid = _int('group_id')
        rid = _int('row_id')

        if wid:
            w = db.session.get(Website, wid)
            result = bool(w and w.is_draft)
        elif pid:
            p = db.session.get(PublicPageContent, pid)
            if p:
                w = db.session.get(Website, p.website_id)
                result = bool(w and w.is_draft)
        elif sid:
            s = db.session.get(PageSection, sid)
            if s and s.page_content_id:
                p = db.session.get(PublicPageContent, s.page_content_id)
                if p:
                    w = db.session.get(Website, p.website_id)
                    result = bool(w and w.is_draft)
        elif gid:
            gr = db.session.get(SectionGroup, gid)
            if gr:
                p = db.session.get(PublicPageContent, gr.page_content_id)
                if p:
                    w = db.session.get(Website, p.website_id)
                    result = bool(w and w.is_draft)
        elif rid:
            r = db.session.get(Row, rid)
            if r:
                p = db.session.get(PublicPageContent, r.page_content_id)
                if p:
                    w = db.session.get(Website, p.website_id)
                    result = bool(w and w.is_draft)
    except Exception:
        pass

    g._draft_ctx = result
    return result


def require_perm(key):
    """Decorator: blocks sub-admins who lack the given permission key.
    For JSON/AJAX requests returns a 403 JSON response with a clear message.
    For page navigations (GET) redirects to the dashboard with a flash notice.

    Special case: a sub-admin with website.draft.edit is granted all
    permissions in _DRAFT_EDIT_COVERS when the request operates on a draft
    website, so they can work freely in the draft without needing any
    live-website permissions."""

    def decorator(f):
        from functools import wraps
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.is_authenticated and current_user.is_sub_admin:
                if not current_user.has_permission(key):
                    # Allow via draft permissions when acting on a draft website.
                    _draft = _is_draft_context()
                    if ((_draft
                         and key in _DRAFT_EDIT_COVERS
                         and current_user.has_permission('website.draft.edit'))
                            or (_draft
                                and key in _DRAFT_PAGES_COVERS
                                and current_user.has_permission('website.draft.pages'))):
                        pass  # grant access
                    else:
                        label = _perm_label(key)
                        msg = (f"You don't have permission to do this "
                               f"({label}). Ask your admin to grant access.")
                        wants_json = (
                                request.is_json
                                or request.method in ('POST', 'PUT', 'PATCH', 'DELETE')
                                or request.headers.get('Accept', '').startswith('application/json')
                                or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                        )
                        if wants_json:
                            return _utf8_json(
                                {'success': False, 'error': msg, 'permission_denied': True}, 403)
                        flash(msg, 'permission_denied')
                        return redirect(url_for('dashboard'))
            return f(*args, **kwargs)

        return wrapped

    return decorator


def get_admin_website():
    """Return the website the current admin user manages.
    Sub-admins share the root admin's website rather than owning their own."""
    if current_user.is_sub_admin:
        root = User.query.get(current_user.root_user_id)
        return root.websites[0] if root and root.websites else None
    return current_user.websites[0] if current_user.websites else None


def is_owner(website):
    """True if the current user (or their root admin) owns this website."""
    if website is None:
        return False
    return website.user_id == current_user.root_user_id


def _effective_perms():
    """Return the permissions dict that governs the current sub-admin.
    When the user belongs to a permission group, the group's permissions
    are used; otherwise the user's own permissions dict."""
    if current_user.permission_group_id and current_user.permission_group:
        return current_user.permission_group.permissions or {}
    return current_user.permissions or {}


def _folder_perm(folder_id, action):
    """Return True if current sub-admin has the given action in the given page folder."""
    if not current_user.is_sub_admin:
        return True
    if not folder_id:
        return False
    perms = _effective_perms()
    fp_map = perms.get('page_folder_perms') or {}
    fp = fp_map.get(str(folder_id))
    if fp is None:
        return False
    if fp == 'full':
        return True
    return action in (fp or [])


def can_access_page(page_id):
    """Sub-admins can access a page editor if they have a direct page grant,
    a folder-level edit grant, a group grant for any group on that page,
    or a section grant for any section on that page.
    All-None (no individual restrictions) means allow all pages."""
    if not current_user.is_sub_admin:
        return True

    # Folder-level edit grant — checked first so it works even when individual
    # page/section restrictions are also configured.
    page_obj = PublicPageContent.query.get(page_id)
    if page_obj and _folder_perm(page_obj.page_folder_id, 'edit'):
        return True

    perms = _effective_perms()
    allowed_pages = perms.get('pages.allowed_ids')
    allowed_groups = perms.get('groups.allowed_ids')
    allowed_sections = perms.get('sections.allowed_ids')

    # No individual restrictions at all → allow all pages
    if allowed_pages is None and allowed_groups is None and allowed_sections is None:
        return True

    # Direct page grant
    if allowed_pages is not None and page_id in allowed_pages:
        return True

    # Any granted group lives on this page
    if allowed_groups:
        page_group_ids = [g.id for g in SectionGroup.query.filter_by(page_content_id=page_id).all()]
        if any(gid in allowed_groups for gid in page_group_ids):
            return True

    # Any granted section lives on this page
    if allowed_sections:
        page_section_ids = [s.id for s in PageSection.query.filter_by(page_content_id=page_id).all()]
        if any(sid in allowed_sections for sid in page_section_ids):
            return True

    return False


def can_access_section(section_id):
    """Sub-admins may be restricted to specific sections, groups, or pages.
    Page-level grants cover all current and future sections on that page.
    Group-level grants cover all current and future sections in that group.
    """
    if not current_user.is_sub_admin:
        return True

    section = PageSection.query.get(section_id)
    if not section:
        return False

    # Folder-level edit grant covers all sections on pages in that folder.
    page_obj = PublicPageContent.query.get(section.page_content_id)
    if page_obj and _folder_perm(page_obj.page_folder_id, 'edit'):
        return True

    perms = _effective_perms()
    allowed_sections = perms.get('sections.allowed_ids')
    allowed_groups = perms.get('groups.allowed_ids')
    allowed_pages = perms.get('pages.allowed_ids')

    if allowed_sections is None and allowed_groups is None and allowed_pages is None:
        return True

    # Page-level grant — covers all sections on this page (including new ones)
    if allowed_pages is not None and section.page_content_id in allowed_pages:
        return True

    # Group-level grant — covers all sections in this group (including new ones)
    if allowed_groups is not None and section.column and section.column.row:
        group_id = section.column.row.section_group_id
        if group_id is not None and group_id in allowed_groups:
            return True

    # Direct section grant
    if allowed_sections is not None and section_id in allowed_sections:
        return True

    return False


def can_access_folder(folder_id):
    """Sub-admins may be restricted to specific asset library folders."""
    if not current_user.is_sub_admin:
        return True
    perms = _effective_perms()
    allowed = perms.get('assets.allowed_folder_ids')
    if allowed is None:
        return True
    return folder_id in (allowed or [])


class PublicUser(UserMixin, db.Model):
    __tablename__ = 'public_user'

    id = db.Column(db.Integer, primary_key=True)

    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False, index=True)

    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    email_verified = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    email_verified_at = db.Column(db.DateTime, nullable=True)
    verification_email_sent_at = db.Column(db.DateTime, nullable=True)
    password_reset_requested_at = db.Column(db.DateTime, nullable=True)
    last_verification_email_sent_at = db.Column(db.DateTime, nullable=True)

    is_banned = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    is_active_public = db.Column(db.Boolean, nullable=False, default=True, server_default='1')

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    website = db.relationship('Website', backref=db.backref('public_users', lazy=True, cascade='all, delete-orphan'))

    __table_args__ = (
        db.UniqueConstraint('website_id', 'username', name='uq_public_user_username_per_website'),
        db.UniqueConstraint('website_id', 'email', name='uq_public_user_email_per_website'),
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @validates('username')
    def normalize_public_username(self, key, value):
        return (value or '').strip().lower()

    @validates('email')
    def normalize_public_email(self, key, value):
        return (value or '').strip().lower()

    def __repr__(self):
        return f"<PublicUser {self.username} website={self.website_id}>"


class ForumThread(db.Model):
    __tablename__ = 'forum_thread'

    id = db.Column(db.Integer, primary_key=True)

    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False, index=True)
    public_user_id = db.Column(db.Integer, db.ForeignKey('public_user.id'), nullable=True, index=True)

    title = db.Column(db.String(180), nullable=False)
    body = db.Column(db.Text, nullable=False)

    is_locked = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    is_hidden = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    is_pinned = db.Column(db.Boolean, nullable=False, default=False, server_default='0')

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    website = db.relationship('Website', backref=db.backref('forum_threads', lazy=True, cascade='all, delete-orphan'))
    author = db.relationship('PublicUser', backref=db.backref('forum_threads', lazy=True))

    reply_count = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    vote_count_cached = db.Column(db.Integer, nullable=False, default=0, server_default='0')

    __table_args__ = (
        db.Index('ix_forum_thread_website_hidden_updated', 'website_id', 'is_hidden', 'updated_at'),
        db.Index('ix_forum_thread_website_hidden_created', 'website_id', 'is_hidden', 'created_at'),
        db.Index('ix_forum_thread_website_hidden_votes', 'website_id', 'is_hidden', 'vote_count_cached'),
        db.Index('ix_forum_thread_website_hidden_replies', 'website_id', 'is_hidden', 'reply_count'),
    )

    def visible_reply_count(self):
        return ForumReply.query.filter_by(
            thread_id=self.id,
            is_hidden=False
        ).count()

    def vote_count(self):
        return ForumThreadVote.query.filter_by(thread_id=self.id).count()

    def user_has_voted(self, public_user):
        if not public_user:
            return False

        return ForumThreadVote.query.filter_by(
            thread_id=self.id,
            public_user_id=public_user.id
        ).first() is not None

    def __repr__(self):
        return f"<ForumThread {self.id} {self.title}>"


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


class ForumReply(db.Model):
    __tablename__ = 'forum_reply'

    id = db.Column(db.Integer, primary_key=True)

    thread_id = db.Column(db.Integer, db.ForeignKey('forum_thread.id'), nullable=False, index=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False, index=True)
    public_user_id = db.Column(db.Integer, db.ForeignKey('public_user.id'), nullable=True, index=True)

    body = db.Column(db.Text, nullable=False)

    is_hidden = db.Column(db.Boolean, nullable=False, default=False, server_default='0')

    vote_count_cached = db.Column(db.Integer, nullable=False, default=0, server_default='0', index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    thread = db.relationship('ForumThread', backref=db.backref('replies', lazy=True, cascade='all, delete-orphan'))
    website = db.relationship('Website', backref=db.backref('forum_replies', lazy=True, cascade='all, delete-orphan'))
    author = db.relationship('PublicUser', backref=db.backref('forum_replies', lazy=True))

    __table_args__ = (
        db.Index('ix_forum_reply_thread_hidden_created', 'thread_id', 'is_hidden', 'created_at'),
        db.Index('ix_forum_reply_website_hidden_created', 'website_id', 'is_hidden', 'created_at'),
    )

    def vote_count(self):
        return ForumReplyVote.query.filter_by(reply_id=self.id).count()

    def user_has_voted(self, public_user):
        if not public_user:
            return False

        return ForumReplyVote.query.filter_by(
            reply_id=self.id,
            public_user_id=public_user.id
        ).first() is not None

    def __repr__(self):
        return f"<ForumReply {self.id} thread={self.thread_id}>"


class ForumThreadVote(db.Model):
    __tablename__ = 'forum_thread_vote'

    id = db.Column(db.Integer, primary_key=True)

    thread_id = db.Column(
        db.Integer,
        db.ForeignKey('forum_thread.id'),
        nullable=False,
        index=True
    )

    website_id = db.Column(
        db.Integer,
        db.ForeignKey('website.id'),
        nullable=False,
        index=True
    )

    public_user_id = db.Column(
        db.Integer,
        db.ForeignKey('public_user.id'),
        nullable=False,
        index=True
    )

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    thread = db.relationship(
        'ForumThread',
        backref=db.backref('votes', lazy=True, cascade='all, delete-orphan')
    )

    public_user = db.relationship(
        'PublicUser',
        backref=db.backref('thread_votes', lazy=True, cascade='all, delete-orphan')
    )

    __table_args__ = (
        db.UniqueConstraint(
            'thread_id',
            'public_user_id',
            name='uq_forum_thread_vote_once_per_user'
        ),
        db.Index('ix_forum_thread_vote_thread_user', 'thread_id', 'public_user_id'),
        db.Index('ix_forum_thread_vote_website_thread', 'website_id', 'thread_id'),
    )


class ForumReplyVote(db.Model):
    __tablename__ = 'forum_reply_vote'

    id = db.Column(db.Integer, primary_key=True)

    reply_id = db.Column(
        db.Integer,
        db.ForeignKey('forum_reply.id'),
        nullable=False,
        index=True
    )

    website_id = db.Column(
        db.Integer,
        db.ForeignKey('website.id'),
        nullable=False,
        index=True
    )

    public_user_id = db.Column(
        db.Integer,
        db.ForeignKey('public_user.id'),
        nullable=False,
        index=True
    )

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    reply = db.relationship(
        'ForumReply',
        backref=db.backref('votes', lazy=True, cascade='all, delete-orphan')
    )

    public_user = db.relationship(
        'PublicUser',
        backref=db.backref('reply_votes', lazy=True, cascade='all, delete-orphan')
    )

    __table_args__ = (
        db.UniqueConstraint(
            'reply_id',
            'public_user_id',
            name='uq_forum_reply_vote_once_per_user'
        ),
        db.Index('ix_forum_reply_vote_reply_user', 'reply_id', 'public_user_id'),
        db.Index('ix_forum_reply_vote_website_reply', 'website_id', 'reply_id'),
    )


class PageComment(db.Model):
    __tablename__ = 'page_comment'

    id = db.Column(db.Integer, primary_key=True)

    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False, index=True)
    page_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'), nullable=False, index=True)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id'), nullable=False, index=True)

    public_user_id = db.Column(db.Integer, db.ForeignKey('public_user.id'), nullable=True, index=True)

    display_name = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)

    is_hidden = db.Column(db.Boolean, nullable=False, default=False, server_default='0', index=True)
    is_approved = db.Column(db.Boolean, nullable=False, default=True, server_default='1', index=True)

    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    website = db.relationship('Website', backref=db.backref('page_comments', lazy=True, cascade='all, delete-orphan'))
    page = db.relationship('PublicPageContent',
                           backref=db.backref('page_comments', lazy=True, cascade='all, delete-orphan'))
    section = db.relationship('PageSection', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    author = db.relationship('PublicUser', backref=db.backref('page_comments', lazy=True))

    like_count_cached = db.Column(db.Integer, nullable=False, default=0, server_default='0', index=True)

    def like_count(self):
        return self.like_count_cached or 0

    def user_has_liked(self, public_user):
        if not public_user:
            return False

        return PageCommentLike.query.filter_by(
            comment_id=self.id,
            public_user_id=public_user.id
        ).first() is not None

    __table_args__ = (
        db.Index('ix_page_comment_section_visible_created', 'section_id', 'is_hidden', 'is_approved', 'created_at'),
        db.Index('ix_page_comment_page_section_created', 'page_id', 'section_id', 'created_at'),
    )

    def __repr__(self):
        return f"<PageComment {self.id} section={self.section_id}>"


class PageCommentLike(db.Model):
    __tablename__ = 'page_comment_like'

    id = db.Column(db.Integer, primary_key=True)

    comment_id = db.Column(
        db.Integer,
        db.ForeignKey('page_comment.id'),
        nullable=False,
        index=True
    )

    website_id = db.Column(
        db.Integer,
        db.ForeignKey('website.id'),
        nullable=False,
        index=True
    )

    section_id = db.Column(
        db.Integer,
        db.ForeignKey('page_section.id'),
        nullable=False,
        index=True
    )

    public_user_id = db.Column(
        db.Integer,
        db.ForeignKey('public_user.id'),
        nullable=False,
        index=True
    )

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    comment = db.relationship(
        'PageComment',
        backref=db.backref('likes', lazy=True, cascade='all, delete-orphan')
    )

    public_user = db.relationship(
        'PublicUser',
        backref=db.backref('comment_likes', lazy=True, cascade='all, delete-orphan')
    )

    __table_args__ = (
        db.UniqueConstraint(
            'comment_id',
            'public_user_id',
            name='uq_page_comment_like_once_per_user'
        ),
        db.Index('ix_page_comment_like_comment_user', 'comment_id', 'public_user_id'),
        db.Index('ix_page_comment_like_section_comment', 'section_id', 'comment_id'),
    )


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
    description = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Draft websites are editing sandboxes — never served publicly.
    # Only one draft per admin user is allowed at a time.
    is_draft = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    public_page_contents = db.relationship('PublicPageContent', backref='website', lazy=True,
                                           cascade="all, delete-orphan")
    tags = db.relationship('Tag', secondary='website_tag', backref=db.backref('websites', lazy=True))

    background_color = db.Column(db.String(500), default='#ffffff')
    text_color = db.Column(db.String(20), default='#000000')
    background_image_url = db.Column(db.String(500), nullable=True)
    background_image_repeat = db.Column(db.Boolean, default=False)
    background_image_repeat_x = db.Column(db.Boolean, default=False)
    background_image_mobile_cover = db.Column(db.Boolean, default=False)
    background_image_zoom = db.Column(db.Integer, default=100)

    public_navbar_items = db.Column(db.JSON, default=list)
    public_navbar_style = db.Column(db.JSON, default=dict)

    forum_enabled = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    forum_show_in_navbar = db.Column(db.Boolean, nullable=False, default=True, server_default='1')
    forum_require_login_to_view = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    forum_require_login_to_post = db.Column(db.Boolean, nullable=False, default=True, server_default='1')
    forum_title = db.Column(db.String(120), nullable=False, default='Forum')
    forum_description = db.Column(db.String(500), nullable=True)

    forum_account_verification_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )

    forum_allow_unverified_login = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default='0'
    )

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
    last_edited_at = db.Column(db.DateTime, nullable=True)
    last_edited_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
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
    # Page-wide custom HTML/CSS/JS injected at the end of <body>
    custom_code = db.Column(db.Text, nullable=True)

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
    custom_code = db.Column(db.Text, nullable=True)
    label = db.Column(db.String(200), nullable=True)
    # Optimistic locking: increment on every content save; client echoes back
    # the version it last saw — server rejects if it no longer matches.
    version = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    updated_at = db.Column(db.DateTime, nullable=True)
    messages = db.relationship('ContactMessage', backref='section', lazy=True, cascade='all, delete-orphan')

    # Define a one-to-one relationship with Column
    column = db.relationship('Column', backref='section', uselist=False)

    def to_dict(self):
        column = self.column
        row = column.row if column else None
        return {
            'id': self.id,
            'page_content_id': self.page_content_id,
            'order': self.order,
            'section_type': self.section_type,
            'content': self.content,
            'custom_code': self.custom_code or '',
            'label': self.label or '',
            'column_id': column.id if column else None,
            'column_number': column.column_number if column else None,
            'row_id': row.id if row else None,
            'row_number': row.row_number if row else None,
            'section_group_id': row.section_group_id if row else None,
            'width': column.width if column else None,
            'version': self.version or 0,
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
    max_width = db.Column(db.Integer, nullable=True)

    background_image_url = db.Column(db.String(500), nullable=True)
    background_image_size = db.Column(db.String(50), default='cover')
    background_image_position = db.Column(db.String(50), default='center')
    background_overlay_color = db.Column(db.String(50), default='transparent')
    background_overlay_opacity = db.Column(db.Float, default=0)


class SectionGroupTemplate(db.Model):
    __tablename__ = 'section_group_template'
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    template_data = db.Column(db.JSON, nullable=False)
    row_count = db.Column(db.Integer, default=0)
    section_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description or '',
            'row_count': self.row_count or 0,
            'section_count': self.section_count or 0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class SectionTemplate(db.Model):
    __tablename__ = 'section_template'
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    section_type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.JSON, nullable=True)
    custom_code = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'section_type': self.section_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class PageTemplate(db.Model):
    __tablename__ = 'page_template'
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    template_data = db.Column(db.JSON, nullable=False)
    group_count = db.Column(db.Integer, default=0)
    section_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description or '',
            'group_count': self.group_count or 0,
            'section_count': self.section_count or 0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


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
    url = db.Column(db.String(500), nullable=False)  # optimized public image
    thumbnail_url = db.Column(db.String(500), nullable=True)  # library/grid thumbnail
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


CALENDAR_STYLE_DEFAULTS = {
    'bg_color': '#00000045',
    'text_color': '#ffffff',
    'header_bg': 'rgba(0,0,0,0.28)',
    'btn_bg': 'rgba(255,255,255,0.10)',
    'btn_text': '#ffffff',
    'today_color': 'rgba(126,226,204,0.14)',
    'border_color': 'rgba(255,255,255,0.16)',
    'subscribe_bg': 'rgba(255,255,255,0.10)',
    'subscribe_text': '#ffffff',
}


class Calendar(db.Model):
    __tablename__ = 'calendar'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    styles = db.Column(db.JSON, nullable=True)
    events = db.relationship('CalendarEvent', backref='calendar', lazy=True, cascade='all, delete-orphan')
    subscribers = db.relationship('CalendarFeedSubscriber', backref='calendar', lazy=True, cascade='all, delete-orphan')
    subscriptions = db.relationship('CalendarSubscription', backref='calendar', lazy=True, cascade='all, delete-orphan')

    def get_styles(self):
        merged = dict(CALENDAR_STYLE_DEFAULTS)
        if self.styles:
            merged.update(self.styles)
        return merged

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description or '',
            'website_id': self.website_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'styles': self.get_styles(),
        }


class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime)
    background_color = db.Column(db.String)
    calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'), nullable=True)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id', name='fk_calendar_event_page_content_id'),
                           nullable=True)
    source = db.Column(db.String(20), nullable=False, default='local')
    subscription_id = db.Column(db.Integer, db.ForeignKey('calendar_subscription.id'), nullable=True)

    def to_dict(self):
        is_external = (self.source or 'local') != 'local'
        return {
            'id': self.id,
            'title': self.title,
            'start': self.start.isoformat(),
            'end': self.end.isoformat() if self.end else None,
            'backgroundColor': self.background_color,
            'calendar_id': self.calendar_id,
            # editable:false tells FullCalendar not to allow drag/resize on external events
            'editable': not is_external,
            # classNames lets CSS target external events without JS hooks
            'classNames': ['ext-cal-event'] if is_external else [],
            'extendedProps': {
                'description': self.description,
                'source': self.source or 'local',
            },
        }


class CalendarFeedSubscriber(db.Model):
    __tablename__ = 'calendar_feed_subscriber'

    id = db.Column(db.Integer, primary_key=True)

    calendar_id = db.Column(
        db.Integer,
        db.ForeignKey('calendar.id'),
        nullable=True,
        index=True
    )

    section_id = db.Column(
        db.Integer,
        db.ForeignKey('page_section.id'),
        nullable=True,
        index=True
    )

    subscriber_hash = db.Column(db.String(64), nullable=False, index=True)

    user_agent = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)

    first_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    request_count = db.Column(db.Integer, nullable=False, default=1)

    __table_args__ = (
        db.UniqueConstraint(
            'calendar_id',
            'subscriber_hash',
            name='unique_calendar_feed_subscriber'
        ),
    )


class CalendarSubscription(db.Model):
    __tablename__ = 'calendar_subscription'
    id = db.Column(db.Integer, primary_key=True)
    calendar_id = db.Column(db.Integer, db.ForeignKey('calendar.id'), nullable=False)
    name = db.Column(db.String(200), nullable=True)
    url = db.Column(db.Text, nullable=False)
    last_synced_at = db.Column(db.DateTime, nullable=True)
    last_sync_error = db.Column(db.Text, nullable=True)
    event_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'calendar_id': self.calendar_id,
            'name': self.name or '',
            'url': self.url,
            'last_synced_at': self.last_synced_at.isoformat() if self.last_synced_at else None,
            'last_sync_error': self.last_sync_error,
            'event_count': self.event_count or 0,
        }


class AIAgent(db.Model):
    __tablename__ = 'ai_agent'
    id = db.Column(db.Integer, primary_key=True)
    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    provider = db.Column(db.String(50), nullable=False, default='openai_compatible')
    api_url = db.Column(db.Text, nullable=True)
    api_key = db.Column(db.Text, nullable=True)
    model = db.Column(db.String(200), nullable=True)
    system_prompt = db.Column(db.Text, nullable=True)
    # 'chat', 'image', or 'both'
    capabilities = db.Column(db.String(20), nullable=False, default='chat', server_default='chat')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, include_key=False):
        key = self.api_key or ''
        masked = ('*' * max(0, len(key) - 4) + key[-4:]) if len(key) > 4 else ('*' * len(key))
        return {
            'id': self.id,
            'name': self.name,
            'provider': self.provider,
            'api_url': self.api_url or '',
            'api_key': self.api_key if include_key else masked,
            'model': self.model or '',
            'system_prompt': self.system_prompt or '',
            'capabilities': self.capabilities or 'chat',
            'created_at': self.created_at.isoformat() if self.created_at else None,
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


class PageVisit(db.Model):
    __tablename__ = 'page_visit'

    id = db.Column(db.Integer, primary_key=True)

    website_id = db.Column(db.Integer, db.ForeignKey('website.id'), nullable=False)
    page_id = db.Column(db.Integer, db.ForeignKey('public_page_content.id'), nullable=False)

    visitor_id = db.Column(db.String(64), nullable=False, index=True)

    path = db.Column(db.String(500), nullable=True)
    referrer = db.Column(db.Text, nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)

    country = db.Column(db.String(100), nullable=True)
    country_iso = db.Column(db.String(10), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    location_source = db.Column(db.String(50), nullable=True)

    asn_number = db.Column(db.Integer, nullable=True)
    asn_organization = db.Column(db.String(255), nullable=True)

    geoip_database_type = db.Column(db.String(100), nullable=True)

    visited_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    website = db.relationship('Website', backref=db.backref('page_visits', lazy=True, cascade='all, delete-orphan'))
    page = db.relationship('PublicPageContent',
                           backref=db.backref('page_visits', lazy=True, cascade='all, delete-orphan'))

    def __repr__(self):
        return f"<PageVisit website={self.website_id} page={self.page_id} visitor={self.visitor_id}>"


class AnalyticsSettings(db.Model):
    __tablename__ = 'analytics_settings'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)

    geoip_enabled = db.Column(db.Boolean, nullable=False, default=False)

    geoip_city_database_path = db.Column(db.String(500), nullable=True)
    geoip_city_database_name = db.Column(db.String(255), nullable=True)
    geoip_city_database_type = db.Column(db.String(100), nullable=True)

    geoip_country_database_path = db.Column(db.String(500), nullable=True)
    geoip_country_database_name = db.Column(db.String(255), nullable=True)
    geoip_country_database_type = db.Column(db.String(100), nullable=True)

    geoip_asn_database_path = db.Column(db.String(500), nullable=True)
    geoip_asn_database_name = db.Column(db.String(255), nullable=True)
    geoip_asn_database_type = db.Column(db.String(100), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('analytics_settings', uselist=False))

    def __repr__(self):
        return f"<AnalyticsSettings user={self.user_id} geoip_enabled={self.geoip_enabled}>"


class SectionAsset(db.Model):
    __tablename__ = 'section_assets'

    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(db.Integer, db.ForeignKey('page_section.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    usage_type = db.Column(db.String(50), nullable=True)
    order = db.Column(db.Integer, default=0)


class AssetFolder(db.Model):
    __tablename__ = 'asset_folder'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    asset_type = db.Column(db.String(30), nullable=True)  # optional: image, audio, pdf, document, misc
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    assets = db.relationship('Asset', backref='parent_folder', lazy=True)


class Asset(db.Model):
    __tablename__ = 'asset'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('asset_folder.id'), nullable=True)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    # Original file preserved pre-conversion (e.g. PNG/JPEG before WebP optimisation)
    original_stored_filename = db.Column(db.String(255), nullable=True)

    url = db.Column(db.String(700), nullable=False)
    thumbnail_url = db.Column(db.String(700), nullable=True)

    asset_type = db.Column(db.String(30), nullable=False, default='misc')
    mime_type = db.Column(db.String(120), nullable=True)
    extension = db.Column(db.String(20), nullable=True)

    file_size = db.Column(db.Integer, nullable=False, default=0)

    unique_play_count = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    play_count = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    last_played_at = db.Column(db.DateTime, nullable=True)

    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    section_usages = db.relationship('SectionAsset', backref='asset', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'original_filename': self.original_filename,
            'url': self.url,
            'thumbnail_url': self.thumbnail_url,
            'asset_type': self.asset_type,
            'mime_type': self.mime_type,
            'extension': self.extension,
            'file_size': self.file_size,
            'file_size_label': format_bytes(self.file_size),
            'play_count': self.play_count or 0,
            'last_played_at': self.last_played_at.isoformat() if self.last_played_at else None,
            'upload_date': self.upload_date.isoformat() if self.upload_date else None
        }


class AssetPlay(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    asset_id = db.Column(
        db.Integer,
        db.ForeignKey('asset.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    visitor_id_hash = db.Column(db.String(64), nullable=False, index=True)

    first_played_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_played_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    play_count = db.Column(db.Integer, nullable=False, default=1, server_default='1')

    asset = db.relationship('Asset', backref=db.backref('play_records', cascade='all, delete-orphan'))

    __table_args__ = (
        db.UniqueConstraint('asset_id', 'visitor_id_hash', name='uq_asset_visitor_play'),
    )


# Hardcoded admin credentials
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin')

# Set the upload folder path
UPLOAD_FOLDER = os.path.join(static_folder, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# API endpoint
ollama_url = 'http://192.168.1.214:11434/api/generate'


# from cryptography.fernet import Fernet
# print(Fernet.generate_key().decode())

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


ASSET_LIBRARY_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'config',
    'asset_library.json'
)

DEFAULT_ASSET_LIBRARY_CONFIG = {
    "max_total_storage_mb": 500,
    "max_single_file_mb": 100,
    "allowed_extensions": {
        "images": ["png", "jpg", "jpeg", "gif", "webp", "svg"],
        "audio": ["mp3", "wav", "ogg", "m4a", "aac"],
        "videos": ["mp4", "webm", "mov", "m4v"],
        "pdfs": ["pdf"],
        "documents": ["txt", "doc", "docx", "xls", "xlsx", "csv", "ppt", "pptx"],
        "misc": ["zip", "json"]
    },
    "blocked_extensions": ["py", "php", "exe", "bat", "cmd", "sh", "js", "html", "htm", "css", "jar"]
}


# Run Flask-Migrate commands to initialize and apply migrations
def run_migrations():
    """
    Apply existing database migrations.

    Do not auto-generate migrations on startup.
    Auto-generating migrations every time the app starts can fail
    and can also create messy/incorrect migration files.
    """
    upgrade_command = [
        'flask',
        '--app',
        'main',
        'db',
        'upgrade'
    ]

    try:
        subprocess.run(
            upgrade_command,
            cwd=os.path.dirname(__file__),
            check=True
        )
        print("Database migrations applied successfully.")

    except subprocess.CalledProcessError as e:
        print("Database migration failed.")
        print("The app will continue starting, but the database may be out of date.")
        print(f"Command failed: {e}")

        # Do NOT raise here if you want the app to keep starting.
        # raise


@app.cli.command("safe-upgrade-db")
def safe_upgrade_db():
    """Safely apply existing database migrations."""
    upgrade_command = [
        'flask',
        '--app',
        'main',
        'db',
        'upgrade'
    ]

    try:
        subprocess.run(
            upgrade_command,
            cwd=os.path.dirname(__file__),
            check=True
        )
        print("Database upgraded successfully.")

    except subprocess.CalledProcessError as e:
        print("Database upgrade failed.")
        print(f"Command failed: {e}")


@app.cli.command("make-migration")
def make_migration():
    """Create a new migration after model changes."""
    message = input("Migration message: ").strip() or "Manual migration"

    # Always upgrade first so Alembic does not complain that the target database is outdated.
    upgrade_command = [
        'flask',
        '--app',
        'main',
        'db',
        'upgrade'
    ]

    migrate_command = [
        'flask',
        '--app',
        'main',
        'db',
        'migrate',
        '-m',
        message
    ]

    try:
        subprocess.run(
            upgrade_command,
            cwd=os.path.dirname(__file__),
            check=True
        )

        subprocess.run(
            migrate_command,
            cwd=os.path.dirname(__file__),
            check=True
        )

        print("Migration created successfully.")
        print("Review the migration file, then run:")
        print("flask --app main db upgrade")

    except subprocess.CalledProcessError as e:
        print("Migration creation failed.")
        print(f"Command failed: {e}")


def user_owns_section(section):
    page = PublicPageContent.query.get(section.page_content_id)
    if not page:
        return False

    website = Website.query.get(page.website_id)
    return bool(website and is_owner(website))


def get_asset_library_config():
    try:
        with open(ASSET_LIBRARY_CONFIG_PATH, 'r', encoding='utf-8') as f:
            loaded = json.load(f)

        config = DEFAULT_ASSET_LIBRARY_CONFIG.copy()
        config.update(loaded)
        return config

    except FileNotFoundError:
        return DEFAULT_ASSET_LIBRARY_CONFIG


def mb_to_bytes(value):
    return int(float(value) * 1024 * 1024)


def get_asset_extension(filename):
    return filename.rsplit('.', 1)[-1].lower().strip() if '.' in filename else ''


def get_asset_type_from_extension(extension):
    config = get_asset_library_config()
    allowed = config.get('allowed_extensions', {})

    for asset_type, extensions in allowed.items():
        if extension in extensions:
            if asset_type == 'images':
                return 'image'
            if asset_type == 'pdfs':
                return 'pdf'
            return asset_type.rstrip('s')

    return 'misc'


def is_allowed_asset_file(filename):
    config = get_asset_library_config()
    extension = get_asset_extension(filename)

    if not extension:
        return False

    if extension in config.get('blocked_extensions', []):
        return False

    allowed_extensions = []
    for extensions in config.get('allowed_extensions', {}).values():
        allowed_extensions.extend(extensions)

    return extension in allowed_extensions


def get_user_asset_storage_bytes(user_id):
    total = db.session.query(func.coalesce(func.sum(Asset.file_size), 0)).filter_by(
        user_id=user_id
    ).scalar()

    return int(total or 0)


def format_bytes(num_bytes):
    num_bytes = float(num_bytes or 0)

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}" if unit != 'B' else f"{int(num_bytes)} {unit}"
        num_bytes /= 1024

    return f"{num_bytes:.1f} PB"


def save_asset_file(file_storage, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    original_filename = secure_filename(file_storage.filename or '')
    extension = get_asset_extension(original_filename)

    if not original_filename or not extension:
        raise ValueError('Invalid filename.')

    if not is_allowed_asset_file(original_filename):
        raise ValueError(f'File type .{extension} is not allowed.')

    file_storage.seek(0, os.SEEK_END)
    file_size = file_storage.tell()
    file_storage.seek(0)

    asset_type = get_asset_type_from_extension(extension)
    mime_type = file_storage.mimetype or mimetypes.guess_type(original_filename)[0]

    base_name = uuid.uuid4().hex

    # Keep images optimized like your current library does.
    if asset_type == 'image' and extension.lower() != 'svg':
        saved = save_optimized_versions(file_storage, output_dir)

        return {
            'original_filename': original_filename,
            'stored_filename': saved['public_filename'],
            'thumbnail_filename': saved['thumb_filename'],
            'original_stored_filename': saved['original_filename'],
            'asset_type': 'image',
            'mime_type': 'image/webp',
            'extension': 'webp',
            'file_size': os.path.getsize(os.path.join(output_dir, saved['public_filename']))
        }

    # SVG and non-image files: save directly.
    stored_filename = f"{base_name}.{extension}"
    filepath = os.path.join(output_dir, stored_filename)

    file_storage.save(filepath)

    return {
        'original_filename': original_filename,
        'stored_filename': stored_filename,
        'thumbnail_filename': None,
        'asset_type': asset_type,
        'mime_type': mime_type,
        'extension': extension,
        'file_size': os.path.getsize(filepath)
    }


@app.route('/admin/dashboard/assets', endpoint='asset_library')
@login_required
def asset_library():
    asset_type = request.args.get('type', 'image')
    folder_id = request.args.get('folder_id')

    valid_types = ['image', 'audio', 'video', 'pdf', 'document', 'misc', 'all']
    if asset_type not in valid_types:
        asset_type = 'image'

    folders_query = AssetFolder.query.filter_by(user_id=current_user.root_user_id)

    if asset_type != 'all':
        folders_query = folders_query.filter(
            or_(
                AssetFolder.asset_type == asset_type,
                AssetFolder.asset_type == None
            )
        )

    all_folders = folders_query.order_by(AssetFolder.name).all()

    # For sub-admins, restrict to allowed folders
    allowed_folder_ids = None
    if current_user.is_sub_admin:
        allowed_folder_ids = _effective_perms().get('assets.allowed_folder_ids')

    if allowed_folder_ids is not None:
        folders = [f for f in all_folders if f.id in allowed_folder_ids]
    else:
        folders = all_folders

    assets_query = Asset.query.filter_by(user_id=current_user.root_user_id)

    if folder_id in ('', None, 'root'):
        # If sub-admin has folder restrictions, redirect to their first allowed folder
        if allowed_folder_ids is not None:
            if folders:
                return redirect(url_for('asset_library', type=asset_type, folder_id=folders[0].id))
            flash("You don't have access to any asset library folders. Ask your admin to grant folder access.",
                  'permission_denied')
            return redirect(url_for('dashboard'))
        assets_query = assets_query.filter(Asset.folder_id == None)
        current_folder = None
    else:
        current_folder = AssetFolder.query.filter_by(
            id=folder_id,
            user_id=current_user.root_user_id
        ).first_or_404()

        # Check sub-admin folder access
        if allowed_folder_ids is not None and current_folder.id not in allowed_folder_ids:
            if folders:
                return redirect(url_for('asset_library', type=asset_type, folder_id=folders[0].id))
            flash("You don't have access to this folder.", 'permission_denied')
            return redirect(url_for('dashboard'))

        assets_query = assets_query.filter(Asset.folder_id == current_folder.id)

    if asset_type != 'all':
        assets_query = assets_query.filter(Asset.asset_type == asset_type)

    assets = assets_query.order_by(Asset.upload_date.desc()).all()

    config = get_asset_library_config()
    used_bytes = get_user_asset_storage_bytes(current_user.root_user_id)
    max_bytes = mb_to_bytes(config.get('max_total_storage_mb', 500))

    storage = {
        'used_bytes': used_bytes,
        'max_bytes': max_bytes,
        'used_label': format_bytes(used_bytes),
        'max_label': format_bytes(max_bytes),
        'percent': min(100, round((used_bytes / max_bytes) * 100, 1)) if max_bytes else 0,
        'remaining_label': format_bytes(max(0, max_bytes - used_bytes))
    }

    return render_template(
        'asset_library.html',
        folders=folders,
        assets=assets,
        current_folder=current_folder,
        current_type=asset_type,
        storage=storage,
        asset_config=config,
        allowed_folder_ids=allowed_folder_ids,
    )


def get_user_asset_folder(user_id):
    return os.path.abspath(
        os.path.join(uploads_folder, str(user_id), 'assets')
    )


def safe_asset_file_path(user_id, filename):
    """
    Build a safe path inside the user's asset folder.
    Prevents accidental deletion outside uploads/<user_id>/assets.
    """
    if not filename:
        return None

    asset_folder = get_user_asset_folder(user_id)
    path = os.path.abspath(os.path.join(asset_folder, os.path.basename(filename)))

    if not path.startswith(asset_folder + os.sep):
        return None

    return path


def get_asset_filenames(asset):
    filenames = set()

    if asset.stored_filename:
        filenames.add(os.path.basename(asset.stored_filename))

    if asset.thumbnail_url:
        filenames.add(os.path.basename(asset.thumbnail_url))

    return filenames


def delete_asset_files_from_disk(asset):
    deleted = []
    missing = []
    errors = []

    for filename in get_asset_filenames(asset):
        path = safe_asset_file_path(asset.user_id, filename)

        if not path:
            errors.append(f"Unsafe path skipped: {filename}")
            continue

        if os.path.exists(path):
            try:
                os.remove(path)
                deleted.append(path)
            except Exception as e:
                errors.append(f"{path}: {e}")
        else:
            missing.append(path)

    return {
        "deleted": deleted,
        "missing": missing,
        "errors": errors
    }


def get_referenced_asset_filenames(user_id):
    """
    Files that the database thinks should exist for this user's new Asset library.
    """
    referenced = set()

    assets = Asset.query.filter_by(user_id=user_id).all()

    for asset in assets:
        referenced.update(get_asset_filenames(asset))

    return referenced


def scan_user_asset_folder(user_id):
    """
    Compare /static/uploads/<user_id>/assets against Asset database rows.
    """
    asset_folder = get_user_asset_folder(user_id)

    referenced = get_referenced_asset_filenames(user_id)
    actual = set()

    if os.path.exists(asset_folder):
        for filename in os.listdir(asset_folder):
            path = safe_asset_file_path(user_id, filename)

            if path and os.path.isfile(path):
                actual.add(filename)

    orphan_files = sorted(actual - referenced)
    missing_files = sorted(referenced - actual)

    orphan_bytes = 0

    for filename in orphan_files:
        path = safe_asset_file_path(user_id, filename)
        if path and os.path.exists(path):
            orphan_bytes += os.path.getsize(path)

    return {
        "user_id": user_id,
        "asset_folder": asset_folder,
        "referenced_count": len(referenced),
        "actual_count": len(actual),
        "orphan_files": orphan_files,
        "missing_files": missing_files,
        "orphan_bytes": orphan_bytes
    }


@app.route('/admin/assets/upload', methods=['POST'])
@login_required
@require_perm('assets.upload')
def asset_upload():
    files = request.files.getlist('asset')
    folder_id = request.form.get('folder_id') or None

    if not files:
        return jsonify({'status': 'error', 'error': 'No files selected.'}), 400

    config = get_asset_library_config()
    max_single_bytes = mb_to_bytes(config.get('max_single_file_mb', 50))
    max_total_bytes = mb_to_bytes(config.get('max_total_storage_mb', 500))
    used_bytes = get_user_asset_storage_bytes(current_user.id)

    incoming_total = 0

    for file in files:
        if not file or not file.filename:
            continue

        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)

        incoming_total += size

        if size > max_single_bytes:
            return jsonify({
                'status': 'error',
                'error': f'"{file.filename}" exceeds the {config.get("max_single_file_mb", 50)} MB single-file limit.'
            }), 400

        if not is_allowed_asset_file(file.filename):
            extension = get_asset_extension(file.filename)
            return jsonify({
                'status': 'error',
                'error': f'"{file.filename}" has a file type that is not allowed: .{extension}'
            }), 400

    if used_bytes + incoming_total > max_total_bytes:
        return jsonify({
            'status': 'error',
            'error': f'Upload would exceed your storage limit. You have {format_bytes(max_total_bytes - used_bytes)} remaining.'
        }), 400

    if folder_id:
        folder = AssetFolder.query.filter_by(
            id=folder_id,
            user_id=current_user.id
        ).first_or_404()
        folder_id = folder.id

    user_folder = os.path.join(uploads_folder, str(current_user.id), 'assets')
    os.makedirs(user_folder, exist_ok=True)

    created_assets = []
    saved_disk_filenames = []

    try:
        for file in files:
            if not file or not file.filename:
                continue

            saved = save_asset_file(file, user_folder)

            saved_disk_filenames.append(saved['stored_filename'])

            if saved.get('thumbnail_filename'):
                saved_disk_filenames.append(saved['thumbnail_filename'])

            asset_url = url_for(
                'static',
                filename=f'uploads/{current_user.id}/assets/{saved["stored_filename"]}'
            )

            thumbnail_url = None
            if saved.get('thumbnail_filename'):
                thumbnail_url = url_for(
                    'static',
                    filename=f'uploads/{current_user.id}/assets/{saved["thumbnail_filename"]}'
                )

            asset = Asset(
                user_id=current_user.id,
                folder_id=folder_id,
                original_filename=saved['original_filename'],
                stored_filename=saved['stored_filename'],
                original_stored_filename=saved.get('original_stored_filename'),
                url=asset_url,
                thumbnail_url=thumbnail_url,
                asset_type=saved['asset_type'],
                mime_type=saved['mime_type'],
                extension=saved['extension'],
                file_size=saved['file_size']
            )

            db.session.add(asset)
            created_assets.append(asset)

        db.session.commit()


    except Exception as e:
        db.session.rollback()
        for filename in saved_disk_filenames:
            path = safe_asset_file_path(current_user.id, filename)
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as cleanup_error:
                    print(f"Failed to clean up upload leftover {path}: {cleanup_error}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 400

    return jsonify({
        'status': 'success',
        'assets': [asset.to_dict() for asset in created_assets],
        'storage': {
            'used_label': format_bytes(get_user_asset_storage_bytes(current_user.id)),
            'max_label': format_bytes(max_total_bytes)
        }
    })


@app.route('/admin/assets/ai-generate', methods=['POST'])
@login_required
@require_perm('assets.ai_generate')
def ai_generate_asset():
    import io as _io, base64 as _b64, requests as _req
    data = request.get_json() or {}
    agent_id = data.get('agent_id')
    prompt = (data.get('prompt') or '').strip()
    size = data.get('size', '1024x1024')
    model_ovr = (data.get('model') or '').strip()
    folder_id = data.get('folder_id') or None
    ref_asset_id = data.get('ref_asset_id') or None

    if not agent_id:
        return _utf8_json({'success': False, 'error': 'Select an AI agent'}, 400)
    if not prompt:
        return _utf8_json({'success': False, 'error': 'Enter a prompt'}, 400)

    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    if agent.provider == 'anthropic':
        return _utf8_json({'success': False,
                           'error': 'Claude does not support image generation. Use an OpenAI agent.'}, 400)

    api_key = decrypt_api_key(agent.api_key or '')

    if agent.provider == 'openai':
        base_url = 'https://api.openai.com'
        model = model_ovr or 'dall-e-3'
    else:
        base_url = (agent.api_url or '').rstrip('/')
        if not base_url:
            return _utf8_json({'success': False, 'error': 'API URL required for custom agents'}, 400)
        model = model_ovr or agent.model or 'dall-e-3'

    valid_sizes = {'1024x1024', '1792x1024', '1024x1792', '512x512', '256x256'}
    if size not in valid_sizes:
        size = '1024x1024'

    auth_headers = {}
    if api_key:
        auth_headers['Authorization'] = f'Bearer {api_key}'

    # Fetch reference image bytes if provided
    ref_image_bytes = None
    ref_image_ext = 'png'
    if ref_asset_id:
        ref_asset = Asset.query.filter_by(id=ref_asset_id, user_id=current_user.id).first()
        if ref_asset:
            try:
                ref_path = os.path.join(uploads_folder, str(current_user.id), 'assets',
                                        ref_asset.stored_filename)
                if os.path.exists(ref_path):
                    with open(ref_path, 'rb') as f:
                        ref_image_bytes = f.read()
                    ref_image_ext = (ref_asset.extension or 'webp').lower()
                else:
                    # Fall back to downloading from URL
                    ref_resp = _req.get(
                        request.host_url.rstrip('/') + ref_asset.url,
                        timeout=30
                    )
                    ref_image_bytes = ref_resp.content
            except Exception as e:
                app.logger.warning(f'ai_generate_asset: could not load ref image: {e}')

    try:
        # ── OpenAI edits endpoint (img2img) ──────────────────────────────
        if ref_image_bytes and agent.provider == 'openai':
            # DALL-E 2 edits require PNG; convert if needed
            import io as _io2
            buf = _io2.BytesIO(ref_image_bytes)
            with Image.open(buf) as im:
                rgba = im.convert('RGBA')
                png_buf = _io2.BytesIO()
                rgba.save(png_buf, 'PNG')
                png_bytes = png_buf.getvalue()

            r = _req.post(
                f'{base_url}/v1/images/edits',
                headers=auth_headers,
                files={
                    'image': ('reference.png', png_bytes, 'image/png'),
                },
                data={'model': 'dall-e-2', 'prompt': prompt, 'n': '1', 'size': size},
                timeout=120
            )

        # ── OpenAI-compatible img2img (base64 init_image) ─────────────────
        elif ref_image_bytes and agent.provider == 'openai_compatible':
            ref_b64 = _b64.b64encode(ref_image_bytes).decode()
            r = _req.post(
                f'{base_url}/v1/images/generations',
                json={
                    'model': model, 'prompt': prompt, 'n': 1, 'size': size,
                    'init_image': ref_b64,  # common convention (Automatic1111, etc.)
                    'image': ref_b64,  # alternative field name
                    'strength': 0.75,
                },
                headers={**auth_headers, 'Content-Type': 'application/json'},
                timeout=120
            )

        # ── Standard text-to-image ────────────────────────────────────────
        else:
            headers = {**auth_headers, 'Content-Type': 'application/json'}
            r = _req.post(
                f'{base_url}/v1/images/generations',
                json={'model': model, 'prompt': prompt, 'n': 1, 'size': size},
                headers=headers,
                timeout=120
            )
    except _req.exceptions.RequestException as e:
        return _utf8_json({'success': False, 'error': f'Request failed: {e}'}, 502)

    if not r.ok:
        return _utf8_json({'success': False, 'error': _extract_api_error(r)}, 502)

    item = (r.json().get('data') or [{}])[0]

    if 'b64_json' in item:
        img_bytes = _b64.b64decode(item['b64_json'])
    elif 'url' in item:
        try:
            img_bytes = _req.get(item['url'], timeout=60).content
        except Exception as e:
            return _utf8_json({'success': False, 'error': f'Failed to download image: {e}'}, 502)
    else:
        return _utf8_json({'success': False, 'error': 'No image data in API response'}, 502)

    user_folder = os.path.join(uploads_folder, str(current_user.id), 'assets')
    os.makedirs(user_folder, exist_ok=True)

    # Log raw response details to help diagnose format issues
    content_type = r.headers.get('Content-Type', 'unknown') if 'url' not in (item if item else {}) else 'downloaded'
    app.logger.info(
        f'ai_generate_asset: received {len(img_bytes)} bytes, '
        f'content-type={content_type}, '
        f'first-bytes={img_bytes[:16].hex()}'
    )

    class _Buf:
        def __init__(self, b): self.stream = _io.BytesIO(b)

    try:
        saved = save_optimized_versions(_Buf(img_bytes), user_folder)
    except Exception as e:
        return _utf8_json({'success': False, 'error': f'Image processing failed: {e}'}, 500)

    safe_slug = secure_filename(prompt[:40].replace(' ', '_')) or 'ai_generated'
    # Derive display name from what PIL actually detected (saved['original_filename'] carries the ext)
    if saved.get('original_filename'):
        orig_ext_detected = saved['original_filename'].rsplit('.', 1)[-1]
    else:
        orig_ext_detected = 'webp'
    display_original = f"ai_{safe_slug}.{orig_ext_detected}"

    asset_url = url_for('static', filename=f'uploads/{current_user.id}/assets/{saved["public_filename"]}')
    thumb_url = url_for('static', filename=f'uploads/{current_user.id}/assets/{saved["thumb_filename"]}')
    file_size = os.path.getsize(os.path.join(user_folder, saved['public_filename']))

    if folder_id:
        folder = AssetFolder.query.filter_by(id=folder_id, user_id=current_user.id).first()
        folder_id = folder.id if folder else None

    asset = Asset(
        user_id=current_user.id,
        folder_id=folder_id,
        original_filename=display_original,
        stored_filename=saved['public_filename'],
        original_stored_filename=saved['original_filename'],
        url=asset_url,
        thumbnail_url=thumb_url,
        asset_type='image',
        mime_type='image/webp',
        extension='webp',
        file_size=file_size
    )
    db.session.add(asset)
    db.session.commit()
    return _utf8_json({'success': True, 'asset': asset.to_dict()})


@app.route('/admin/assets/download/<int:asset_id>')
@login_required
def download_asset(asset_id):
    asset = Asset.query.filter_by(
        id=asset_id,
        user_id=current_user.id
    ).first_or_404()

    user_asset_dir = os.path.join(uploads_folder, str(current_user.id), 'assets')

    # Prefer the preserved original (e.g. PNG/JPEG) over the converted WebP
    serve_filename = asset.stored_filename
    if asset.original_stored_filename:
        orig_path = os.path.join(user_asset_dir, asset.original_stored_filename)
        if os.path.exists(orig_path):
            serve_filename = asset.original_stored_filename

    asset_path = os.path.join(user_asset_dir, serve_filename)
    if not os.path.exists(asset_path):
        return "File not found", 404

    return send_file(
        asset_path,
        as_attachment=True,
        download_name=asset.original_filename
    )


@app.route('/admin/assets/create_folder', methods=['POST'])
@login_required
@require_perm('assets.folders')
def create_asset_folder():
    data = request.get_json() or {}

    name = (data.get('name') or '').strip()
    asset_type = (data.get('asset_type') or None)

    if not name:
        return jsonify({'status': 'error', 'message': 'Folder name is required.'}), 400

    folder = AssetFolder(
        name=name,
        user_id=current_user.id,
        asset_type=asset_type if asset_type != 'all' else None
    )

    db.session.add(folder)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'folder_id': folder.id
    })


@app.route('/admin/assets/move', methods=['POST'])
@login_required
def move_asset():
    data = request.get_json() or {}

    asset_id = data.get('asset_id')
    folder_id = data.get('folder_id')

    if folder_id == 'root':
        folder_id = None

    asset = Asset.query.filter_by(
        id=asset_id,
        user_id=current_user.id
    ).first_or_404()

    if folder_id:
        folder = AssetFolder.query.filter_by(
            id=folder_id,
            user_id=current_user.id
        ).first_or_404()

        asset.folder_id = folder.id
    else:
        asset.folder_id = None

    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/admin/assets/delete/<int:asset_id>', methods=['POST'])
@login_required
@require_perm('assets.delete')
def delete_asset(asset_id):
    asset = Asset.query.filter_by(
        id=asset_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        # Keep filenames before deleting the DB row.
        files_to_delete = list(get_asset_filenames(asset))

        # Delete DB record first.
        db.session.delete(asset)
        db.session.commit()

        # Then delete files from disk after DB commit succeeds.
        disk_result = {
            "deleted": [],
            "missing": [],
            "errors": []
        }

        for filename in files_to_delete:
            fake_asset = type("TempAssetRef", (), {
                "user_id": current_user.id,
                "stored_filename": filename,
                "thumbnail_url": None
            })()

            result = delete_asset_files_from_disk(fake_asset)

            disk_result["deleted"].extend(result["deleted"])
            disk_result["missing"].extend(result["missing"])
            disk_result["errors"].extend(result["errors"])

        return jsonify({
            'status': 'success',
            'disk_cleanup': disk_result
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/admin/assets/root', methods=['GET'])
@login_required
def get_asset_library_root():
    asset_type = request.args.get('type', 'image')

    folders_query = AssetFolder.query.filter_by(user_id=current_user.root_user_id)

    if asset_type != 'all':
        folders_query = folders_query.filter(
            or_(
                AssetFolder.asset_type == asset_type,
                AssetFolder.asset_type == None
            )
        )

    all_folders = folders_query.order_by(AssetFolder.name).all()

    # Restrict sub-admins to their allowed folder list
    allowed_folder_ids = None
    if current_user.is_sub_admin:
        allowed_folder_ids = _effective_perms().get('assets.allowed_folder_ids')

    if allowed_folder_ids is not None:
        folders = [f for f in all_folders if f.id in allowed_folder_ids]
        # Root-level assets are not visible when the sub-admin has folder restrictions
        assets = []
    else:
        folders = all_folders
        assets_query = Asset.query.filter_by(
            user_id=current_user.root_user_id,
            folder_id=None
        )
        if asset_type != 'all':
            assets_query = assets_query.filter_by(asset_type=asset_type)
        assets = assets_query.order_by(Asset.upload_date.desc()).all()

    return jsonify({
        'folders': [
            {
                'id': folder.id,
                'name': folder.name,
                'asset_type': folder.asset_type
            }
            for folder in folders
        ],
        'assets': [asset.to_dict() for asset in assets]
    })


@app.route('/admin/assets/folder/<int:folder_id>', methods=['GET'])
@login_required
def get_asset_library_folder(folder_id):
    folder = AssetFolder.query.filter_by(
        id=folder_id,
        user_id=current_user.root_user_id
    ).first_or_404()

    # Enforce sub-admin folder restrictions
    if current_user.is_sub_admin:
        allowed = _effective_perms().get('assets.allowed_folder_ids')
        if allowed is not None and folder.id not in allowed:
            return _utf8_json(
                {'success': False, 'error': "You don't have access to this folder.",
                 'permission_denied': True}, 403)

    asset_type = request.args.get('type', 'image')

    assets_query = Asset.query.filter_by(
        user_id=current_user.root_user_id,
        folder_id=folder.id
    )

    if asset_type != 'all':
        assets_query = assets_query.filter_by(asset_type=asset_type)

    assets = assets_query.order_by(Asset.upload_date.desc()).all()

    return jsonify({
        'folder': {
            'id': folder.id,
            'name': folder.name,
            'asset_type': folder.asset_type
        },
        'assets': [asset.to_dict() for asset in assets]
    })


# @app.route('/add_assets_to_section', methods=['POST'])
# @login_required
# def add_assets_to_section():
#     data = request.get_json() or {}
#
#     section_id = data.get('section_id')
#     asset_ids = data.get('asset_ids') or []
#     usage_type = data.get('usage_type') or 'section-image'
#
#     section = PageSection.query.get_or_404(section_id)
#     page = PublicPageContent.query.get_or_404(section.page_content_id)
#     website = Website.query.get_or_404(page.website_id)
#
#     if not is_owner(website):
#         return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
#
#     for asset_id in asset_ids:
#         asset = Asset.query.filter_by(
#             id=asset_id,
#             user_id=current_user.id
#         ).first()
#
#         if not asset:
#             continue
#
#         # Image sections should only accept images.
#         if section.section_type in ['image', 'image_gallery', 'images'] and asset.asset_type != 'image':
#             continue
#
#         max_order = db.session.query(func.max(SectionAsset.order)).filter_by(
#             section_id=section.id
#         ).scalar() or 0
#
#         link = SectionAsset(
#             section_id=section.id,
#             asset_id=asset.id,
#             usage_type=usage_type,
#             order=max_order + 1
#         )
#
#         db.session.add(link)
#
#     db.session.commit()
#
#     return jsonify({'status': 'success'})

@app.route('/update_page_colors/<int:page_id>', methods=['PUT'])
@login_required
@require_perm('pages.edit')
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

def normalize_admin_url_key(value):
    value = (value or '').strip().lower()
    value = re.sub(r'[^a-z0-9_-]+', '-', value)
    value = value.strip('-_')
    return value


def admin_url_key_is_enabled():
    return bool(
        current_user.is_authenticated
        and getattr(current_user, 'admin_url_key_enabled', False)
        and getattr(current_user, 'admin_url_key', None)
    )


def admin_url_key_required_for_user(user):
    return bool(
        user
        and getattr(user, 'admin_url_key_enabled', False)
        and getattr(user, 'admin_url_key', None)
    )


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

        sections = [s for s in sections if s.column and s.column.row]
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
                'max_width': group.max_width,
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
@require_perm('sections.groups')
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


def _serialize_group(group):
    """Serialize a SectionGroup and all its rows/columns/sections to a dict."""
    rows = Row.query.filter_by(section_group_id=group.id).order_by(Row.row_number).all()
    rows_data = []
    total_sections = 0
    for row in rows:
        cols = Column.query.filter_by(row_id=row.id).order_by(Column.column_number).all()
        cols_data = []
        for col in cols:
            section = col.section
            col_dict = {
                'column_number': col.column_number,
                'width': col.width,
                'section': {
                    'section_type': section.section_type,
                    'content': section.content,
                } if section else None,
            }
            cols_data.append(col_dict)
            if section:
                total_sections += 1
        rows_data.append({'row_number': row.row_number, 'columns': cols_data})

    return {
        'styles': {
            'background_color': group.background_color or 'transparent',
            'background_opacity': group.background_opacity or 1,
            'padding': group.padding or 0,
            'border_radius': group.border_radius or 0,
            'max_width': group.max_width,
            'background_image_url': group.background_image_url,
            'background_image_size': group.background_image_size or 'cover',
            'background_image_position': group.background_image_position or 'center',
            'background_overlay_color': group.background_overlay_color or 'transparent',
            'background_overlay_opacity': group.background_overlay_opacity or 0,
        },
        'rows': rows_data,
    }, len(rows), total_sections


def _instantiate_group_template(page_content_id, template_data, group_name):
    """Create a SectionGroup on a page from serialized template data."""
    group_count = SectionGroup.query.filter_by(page_content_id=page_content_id).count()
    styles = template_data.get('styles', {})

    new_group = SectionGroup(
        page_content_id=page_content_id,
        name=group_name,
        group_order=group_count + 1,
        background_color=styles.get('background_color', 'transparent'),
        background_opacity=styles.get('background_opacity', 1),
        padding=styles.get('padding', 0),
        border_radius=styles.get('border_radius', 0),
        max_width=styles.get('max_width'),
        background_image_url=styles.get('background_image_url'),
        background_image_size=styles.get('background_image_size', 'cover'),
        background_image_position=styles.get('background_image_position', 'center'),
        background_overlay_color=styles.get('background_overlay_color', 'transparent'),
        background_overlay_opacity=styles.get('background_overlay_opacity', 0),
    )
    db.session.add(new_group)
    db.session.flush()

    max_row = db.session.query(func.max(Row.row_number)).filter_by(
        page_content_id=page_content_id
    ).scalar() or 0

    for row_data in template_data.get('rows', []):
        max_row += 1
        new_row = Row(
            page_content_id=page_content_id,
            row_number=max_row,
            section_group_id=new_group.id,
        )
        db.session.add(new_row)
        db.session.flush()

        for col_data in row_data.get('columns', []):
            section_data = col_data.get('section')
            new_section = None
            if section_data:
                new_section = PageSection(
                    section_type=section_data['section_type'],
                    content=section_data.get('content'),
                    order=col_data['column_number'],
                    page_content_id=page_content_id,
                )
                db.session.add(new_section)
                db.session.flush()

            new_col = Column(
                row_id=new_row.id,
                column_number=col_data['column_number'],
                width=col_data.get('width', 100),
                section_id=new_section.id if new_section else None,
            )
            db.session.add(new_col)

    db.session.commit()
    return new_group


@app.route('/admin/section_group_templates', methods=['GET'])
@login_required
def list_section_group_templates():
    website = get_admin_website()
    if not website:
        return jsonify({'templates': []})
    templates = SectionGroupTemplate.query.filter_by(website_id=website.id).order_by(
        SectionGroupTemplate.created_at.desc()
    ).all()
    return jsonify({'templates': [t.to_dict() for t in templates]})


@app.route('/admin/section_group_templates/save/<int:group_id>', methods=['POST'])
@login_required
@require_perm('sections.templates')
def save_section_group_template(group_id):
    group = SectionGroup.query.get_or_404(group_id)
    page = PublicPageContent.query.get_or_404(group.page_content_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    name = (data.get('name') or group.name or 'Template').strip()

    template_data, row_count, section_count = _serialize_group(group)

    tmpl = SectionGroupTemplate(
        website_id=website.id,
        name=name,
        description=(data.get('description') or '').strip() or None,
        template_data=template_data,
        row_count=row_count,
        section_count=section_count,
    )
    db.session.add(tmpl)
    db.session.commit()
    return jsonify({'success': True, 'template': tmpl.to_dict()}), 201


@app.route('/admin/section_group_templates/<int:template_id>/delete', methods=['POST'])
@login_required
@require_perm('sections.templates')
def delete_section_group_template(template_id):
    tmpl = SectionGroupTemplate.query.get_or_404(template_id)
    website = Website.query.get_or_404(tmpl.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    db.session.delete(tmpl)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/create_section_group_from_template/<int:page_content_id>/<int:template_id>', methods=['POST'])
@login_required
@require_perm('sections.templates')
def create_section_group_from_template(page_content_id, template_id):
    page = PublicPageContent.query.get_or_404(page_content_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    tmpl = SectionGroupTemplate.query.get_or_404(template_id)
    try:
        new_group = _instantiate_group_template(page_content_id, tmpl.template_data, tmpl.name)
        return jsonify({'success': True, 'group_id': new_group.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/duplicate_section_group/<int:group_id>', methods=['POST'])
@login_required
@require_perm('sections.groups')
def duplicate_section_group(group_id):
    group = SectionGroup.query.get_or_404(group_id)
    page = PublicPageContent.query.get_or_404(group.page_content_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    try:
        template_data, _, _ = _serialize_group(group)
        new_group = _instantiate_group_template(group.page_content_id, template_data, group.name)
        return jsonify({'success': True, 'group_id': new_group.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete_section_group/<int:group_id>', methods=['DELETE'])
@login_required
@require_perm('sections.groups')
def delete_section_group(group_id):
    try:
        group = SectionGroup.query.get_or_404(group_id)

        page_content = PublicPageContent.query.get_or_404(group.page_content_id)
        website = Website.query.get_or_404(page_content.website_id)

        if not is_owner(website):
            return jsonify({
                'success': False,
                'error': 'Unauthorized.'
            }), 403

        rows = Row.query.filter_by(section_group_id=group.id).all()

        for row in rows:
            columns = Column.query.filter_by(row_id=row.id).all()

            for column in columns:
                section = column.section

                if section:
                    SectionImage.query.filter_by(section_id=section.id).delete()
                    CalendarEvent.query.filter(
                        CalendarEvent.section_id == section.id,
                        CalendarEvent.calendar_id == None
                    ).delete()
                    db.session.delete(section)

                db.session.delete(column)

            db.session.delete(row)

        db.session.delete(group)

        db.session.flush()

        # Re-number remaining groups on this page
        remaining_groups = SectionGroup.query.filter_by(
            page_content_id=page_content.id
        ).order_by(SectionGroup.group_order, SectionGroup.id).all()

        for index, remaining_group in enumerate(remaining_groups, start=1):
            remaining_group.group_order = index

        # Re-number remaining rows on this page
        remaining_rows = Row.query.filter_by(
            page_content_id=page_content.id
        ).order_by(Row.row_number, Row.id).all()

        for index, remaining_row in enumerate(remaining_rows, start=1):
            remaining_row.row_number = index

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting section group: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/update_section_group/<int:group_id>', methods=['PUT'])
@login_required
@require_perm('sections.groups')
def update_section_group(group_id):
    try:
        group = SectionGroup.query.get_or_404(group_id)
        data = request.get_json()

        name = data.get('name')
        background_color = data.get('background_color')
        padding = data.get('padding')
        border_radius = data.get('border_radius')
        max_width = data.get('max_width')

        if name is not None:
            group.name = name
            group.anchor_slug = slugify_anchor(name)

        if background_color is not None:
            group.background_color = background_color

        if padding is not None:
            group.padding = int(padding)

        if border_radius is not None:
            group.border_radius = int(border_radius)

        if max_width is not None:
            try:
                max_width_value = int(max_width or 0)
            except (TypeError, ValueError):
                max_width_value = 0

            # 0 means full width / no cap
            group.max_width = max_width_value if max_width_value > 0 else None

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
                'anchor_slug': group.anchor_slug,
                'max_width': group.max_width
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
    data = request.json or {}

    section_group_id = data.get('section_group_id')

    if not section_group_id:
        return jsonify({
            'success': False,
            'error': 'Rows must belong to a group.'
        }), 400

    group = SectionGroup.query.filter_by(
        id=section_group_id,
        page_content_id=row.page_content_id
    ).first_or_404()

    row.section_group_id = group.id
    db.session.commit()

    return jsonify({"success": True})


@app.route('/update_section_group_order', methods=['POST'])
@login_required
@require_perm('sections.groups')
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


def update_link_card_section(section, form_data):
    def clean(value, fallback=''):
        return (value or fallback).strip()

    def safe_int(value, fallback, min_value=None, max_value=None):
        try:
            number = int(value or fallback)
        except (TypeError, ValueError):
            number = fallback

        if min_value is not None:
            number = max(min_value, number)

        if max_value is not None:
            number = min(max_value, number)

        return number

    def safe_float(value, fallback, min_value=None, max_value=None):
        try:
            number = float(value or fallback)
        except (TypeError, ValueError):
            number = fallback

        if min_value is not None:
            number = max(min_value, number)

        if max_value is not None:
            number = min(max_value, number)

        return number

    section.content = {
        'header': clean(form_data.get('link_card_header'), 'Link Card'),
        'body': clean(form_data.get('link_card_body'), ''),
        'footer': clean(form_data.get('link_card_footer'), ''),
        'url': clean(form_data.get('link_card_url'), '#'),

        # image/background
        'background_image_url': clean(form_data.get('link_card_background_image_url'), ''),
        'background_color': clean(form_data.get('link_card_background_color'), '#1f232b'),
        'text_color': clean(form_data.get('link_card_text_color'), '#ffffff'),
        'overlay_color': clean(form_data.get('link_card_overlay_color'), '#000000'),
        'overlay_opacity': safe_float(
            form_data.get('link_card_overlay_opacity'),
            0.25,
            0,
            1
        ),

        # presentation
        'width': safe_int(
            form_data.get('link_card_width'),
            420,
            120,
            1400
        ),
        'height': safe_int(
            form_data.get('link_card_height'),
            240,
            120,
            800
        ),
        'border_radius': safe_int(
            form_data.get('link_card_border_radius'),
            18,
            0,
            80
        ),
        'open_in_new_tab': form_data.get('link_card_open_new_tab') == 'on'
    }

    return section


@app.route('/update_editor_group_and_row_order', methods=['POST'])
@login_required
def update_editor_group_and_row_order():
    try:
        data = request.get_json()
        group_ids = data.get('group_ids', [])
        rows = data.get('rows', [])

        # Use an IMMEDIATE transaction so SQLite acquires the write lock
        # upfront — prevents a second concurrent reorder from reading stale
        # row numbers between our read and write.
        db.session.execute(db.text("BEGIN IMMEDIATE"))

        for index, group_id in enumerate(group_ids, start=1):
            group = SectionGroup.query.get(group_id)
            if group:
                group.group_order = index

        for row_item in rows:
            row = Row.query.get(row_item.get('row_id'))
            section_group_id = row_item.get('section_group_id')
            if row:
                if not section_group_id:
                    db.session.rollback()
                    return jsonify({'success': False, 'error': 'Rows must belong to a group.'}), 400
                row.row_number = row_item.get('row_number')
                row.section_group_id = section_group_id

        db.session.commit()
        return jsonify({'success': True})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating editor order: {e}")
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
@require_perm('sections.groups')
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


@app.route('/admin/register', methods=['GET', 'POST'])
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

        ensure_default_website(new_user)

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

ADMIN_PROTECTED_PREFIXES = (
    '/admin',
    '/dashboard',
    '/create_website',
    '/create_page',
    '/edit_website',
    '/edit_website_style',
    '/edit_page',
    '/duplicate_page',
    '/replace_page',
    '/delete_page',
    '/delete_website',
    '/library',
    '/saved_colors',
)


@app.before_request
def update_last_seen():
    """Update last_seen_at for authenticated admin users, throttled to once per minute."""
    if (current_user.is_authenticated
            and not getattr(current_user, 'is_anonymous', True)
            and request.endpoint not in ('static', None)):
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        last = current_user.last_seen_at
        if last is None or (now - last).total_seconds() > 60:
            current_user.last_seen_at = now
            db.session.commit()


@app.before_request
def require_admin_url_key_for_admin_routes():
    if request.endpoint in ('static',):
        return None

    # Allow public pages and public contact form
    public_endpoints = {
        'home_page',
        'public_page_by_slug',
        'public_page',
        'send_email',
        'serve_static',
        'login',
        'two_factor_login',
        'register',
        'logout',
        'forgot_password',
        'reset_password',
        'emergency_login',
        'request_username'
    }

    if request.endpoint in public_endpoints:
        return None

    path = request.path or ''

    is_admin_like_path = path.startswith(ADMIN_PROTECTED_PREFIXES)

    if not is_admin_like_path:
        return None

    if is_admin_like_path:
        admin_user = User.query.first()

        if admin_url_key_required_for_user(admin_user) and not session.get('admin_path_verified'):
            return "Not Found", 404

    if admin_url_key_is_enabled() and not session.get('admin_path_verified'):
        return "Not Found", 404

    return None


@app.route('/admin/forgot-password', methods=['GET', 'POST'])
@app.route('/admin/forgot-password/<admin_key>', methods=['GET', 'POST'])
def forgot_password(admin_key=None):
    admin_user = User.query.first()

    if admin_url_key_required_for_user(admin_user):
        if admin_key != admin_user.admin_url_key:
            return "Not Found", 404

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        # Always show a generic success message so we do not reveal valid emails.
        generic_message = 'If that email matches the admin account and email sending is configured, a reset link has been sent.'

        user = User.query.filter_by(email=email).first()

        if user:
            email_settings = get_email_settings()

            if email_settings and email_settings.is_active:
                token = generate_password_reset_token(user)
                reset_url = url_for('reset_password', token=token, _external=True)

                print("")
                print("========================================")
                print("UWEBIA PASSWORD RESET LINK")
                print(f"User: {user.username}")
                print(f"Email: {user.email}")
                print(f"Reset URL: {reset_url}")
                print("Expires in 30 minutes")
                print("========================================")
                print("")

                body = f"""A password reset was requested for your Uwebia admin account.

Reset your password here:
{reset_url}

This link expires in 30 minutes.

If you did not request this, you can ignore this email.
"""

                try:
                    send_account_recovery_email(
                        user.email,
                        'Reset your Uwebia admin password',
                        body
                    )
                except Exception as e:
                    print(f"Password reset email failed: {e}")

        flash(generic_message, 'success')
        return redirect(request.path)

    return render_template(
        'forgot_password.html',
        admin_key=admin_key
    )


@app.route('/admin/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user, error = verify_password_reset_token(token)

    if error:
        flash(error, 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not password:
            flash('Please enter a new password.', 'error')
            return redirect(request.path)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(request.path)

        user.set_password(password)

        # Changing password should force a clean login.
        db.session.commit()

        flash('Password updated successfully. Please log in.', 'success')
        return redirect(get_admin_login_url_for_user(user))

    return render_template(
        'reset_password.html',
        token=token
    )


def get_recovery_serializer():
    return URLSafeTimedSerializer(app.secret_key)


def generate_password_reset_token(user):
    serializer = get_recovery_serializer()

    return serializer.dumps(
        {
            'user_id': user.id,
            'purpose': 'password_reset'
        },
        salt='uwebia-password-reset'
    )


def verify_password_reset_token(token, max_age_seconds=1800):
    serializer = get_recovery_serializer()

    try:
        data = serializer.loads(
            token,
            salt='uwebia-password-reset',
            max_age=max_age_seconds
        )
    except SignatureExpired:
        return None, 'This password reset link has expired.'
    except BadSignature:
        return None, 'This password reset link is invalid.'

    if data.get('purpose') != 'password_reset':
        return None, 'This password reset link is invalid.'

    user = User.query.get(data.get('user_id'))

    if not user:
        return None, 'This password reset link is invalid.'

    return user, None


def send_account_recovery_email(to_email, subject, body):
    settings = get_email_settings()

    if not settings or not settings.is_active:
        raise RuntimeError('Email server is not configured or active.')

    if not settings.smtp_host or not settings.smtp_port or not settings.smtp_username or not settings.smtp_password or not settings.from_email:
        raise RuntimeError('Email server settings are incomplete.')

    if settings.use_tls and settings.use_ssl:
        raise RuntimeError('Email server cannot use both TLS and SSL.')

    msg = MIMEMultipart()
    msg['From'] = (
        f"{settings.from_name} <{settings.from_email}>"
        if settings.from_name else settings.from_email
    )
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    if settings.use_ssl:
        server = smtplib.SMTP_SSL(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10
        )
    else:
        server = smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10
        )

        if settings.use_tls:
            server.starttls()

    try:
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)
    finally:
        server.quit()


@app.route('/admin/request-username', methods=['GET', 'POST'])
@app.route('/admin/request-username/<admin_key>', methods=['GET', 'POST'])
def request_username(admin_key=None):
    admin_user = User.query.first()

    if admin_url_key_required_for_user(admin_user):
        if admin_key != admin_user.admin_url_key:
            return "Not Found", 404

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        generic_message = 'If that email matches the admin account and email sending is configured, the username has been sent.'

        user = User.query.filter_by(email=email).first()

        if user:
            email_settings = get_email_settings()

            if email_settings and email_settings.is_active:
                login_url = get_admin_login_url_for_user(user)

                print("")
                print("========================================")
                print("UWEBIA USERNAME RECOVERY")
                print(f"Email: {user.email}")
                print(f"Username: {user.username}")
                print(f"Login URL: {login_url}")
                print("========================================")
                print("")

                body = f"""Your Uwebia admin username is:

{user.username}

Login here:
{login_url}

If you did not request this, you can ignore this email.
"""

                try:
                    send_account_recovery_email(
                        user.email,
                        'Your Uwebia admin username',
                        body
                    )
                except Exception as e:
                    print(f"Username recovery email failed: {e}")

        flash(generic_message, 'success')
        return redirect(request.path)

    return render_template(
        'request_username.html',
        admin_key=admin_key
    )


def get_admin_login_url_for_user(user):
    if user and user.admin_url_key_enabled and user.admin_url_key:
        return url_for('login', admin_key=user.admin_url_key, _external=True)

    return url_for('login', _external=True)


@app.route('/admin/dashboard/settings/2fa/dismiss-warning', methods=['POST'])
@login_required
def dismiss_two_factor_warning():
    current_user.two_factor_needs_attention = False
    current_user.two_factor_disabled_reason = None
    current_user.two_factor_disabled_at = None

    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': '2FA warning dismissed.'
    })


@app.route('/admin/2fa', methods=['GET', 'POST'])
@app.route('/admin/2fa/<admin_key>', methods=['GET', 'POST'])
def two_factor_login(admin_key=None):
    user_id = session.get('pre_2fa_user_id')

    if not user_id:
        return redirect(url_for('login', admin_key=admin_key) if admin_key else url_for('login'))

    user = db.session.get(User, user_id)

    if not user:
        clear_pending_two_factor_code()
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_admin_key', None)
        return redirect(url_for('login', admin_key=admin_key) if admin_key else url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()

        pending_error = get_pending_two_factor_error(user.id, 'login')

        if pending_error:
            clear_pending_two_factor_code()
            session.pop('pre_2fa_user_id', None)
            session.pop('pre_2fa_admin_key', None)

            flash(pending_error, 'error')
            return redirect(url_for('login', admin_key=admin_key) if admin_key else url_for('login'))

        expected_hash = session.get('pending_2fa_code_hash')

        if not expected_hash or not check_password_hash(expected_hash, code):
            flash('Invalid verification code.', 'error')
            return redirect(request.path)

        login_user(user)

        if admin_url_key_required_for_user(user):
            session['admin_path_verified'] = True

        _stamp_login(user)
        clear_pending_two_factor_code()
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_admin_key', None)

        flash('Logged in successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('two_factor_login.html', admin_key=admin_key)


def disable_user_2fa(user, reason=None, needs_attention=True):
    user.two_factor_enabled = False
    user.two_factor_email = None
    user.two_factor_activated_at = None
    user.two_factor_last_email_settings_version = None

    user.two_factor_disabled_reason = reason
    user.two_factor_disabled_at = datetime.now(timezone.utc).replace(tzinfo=None)
    user.two_factor_needs_attention = bool(needs_attention)


@app.route('/admin/login', methods=['GET', 'POST'])
@app.route('/admin/login/<admin_key>', methods=['GET', 'POST'])
def login(admin_key=None):
    # Force setup if no user exists
    if User.query.count() == 0:
        return redirect(url_for('register'))

    admin_user = User.query.first()

    if admin_url_key_required_for_user(admin_user):
        expected_key = admin_user.admin_url_key

        if admin_key != expected_key:
            return "Not Found", 404

        session['admin_path_verified'] = True

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Determine whether 2FA is required and which address to use.
            # Main admins: their own two_factor_enabled flag + their stored email.
            # Sub-admins: inherit the requirement when their parent has 2FA on;
            #             code goes to the sub-admin's own account email.
            needs_2fa = False
            two_fa_email = None

            if user.two_factor_enabled:
                email_settings = get_email_settings()
                current_fingerprint = get_email_settings_fingerprint(email_settings)

                if current_fingerprint != user.two_factor_last_email_settings_version:
                    disable_user_2fa(
                        user,
                        reason='email server settings changed',
                        needs_attention=True
                    )
                    db.session.commit()
                    flash('2FA was disabled because email server settings changed. Please log in again.', 'error')
                    return redirect(request.path)

                needs_2fa = True
                two_fa_email = user.two_factor_email or user.email

            elif user.is_sub_admin:
                parent = db.session.get(User, user.parent_user_id)
                if parent and parent.two_factor_enabled:
                    needs_2fa = True
                    two_fa_email = user.email  # always the sub-admin's own email

            if needs_2fa:
                # If a code was already sent within the last 30 seconds (e.g.
                # from a double-click or back-button resubmit), skip generating
                # and emailing a new one — just redirect to the waiting page.
                if _2fa_recently_sent(user.id):
                    session['pre_2fa_user_id'] = user.id
                    session['pre_2fa_admin_key'] = admin_key
                    return redirect(
                        url_for('two_factor_login', admin_key=admin_key)
                        if admin_key else url_for('two_factor_login'))

                code = generate_two_factor_code()
                set_pending_two_factor_code(user.id, code, 'login')

                print("")
                print("========================================")
                print("UWEBIA 2FA LOGIN CODE")
                print(f"User: {user.username}")
                print(f"Email: {two_fa_email}")
                print(f"Code: {code}")
                print("Expires in 10 minutes")
                print("========================================")
                print("")

                try:
                    send_two_factor_email(two_fa_email, code, purpose='login')
                except Exception as e:
                    clear_pending_two_factor_code()
                    flash(f'Could not send 2FA login code: {str(e)}', 'error')
                    return redirect(request.path)

                session['pre_2fa_user_id'] = user.id
                session['pre_2fa_admin_key'] = admin_key

                return redirect(
                    url_for('two_factor_login', admin_key=admin_key) if admin_key else url_for('two_factor_login'))

            login_user(user)

            if admin_url_key_required_for_user(user):
                session['admin_path_verified'] = True

            _stamp_login(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(request.path)

    return render_template(
        'login.html',
        admin_key=admin_key
    )


@app.route('/admin/logout')
@login_required
def logout():
    user = current_user
    login_key = user.admin_url_key if user.admin_url_key_enabled and user.admin_url_key else None

    logout_user()
    session.pop('admin_path_verified', None)

    flash('Logged out successfully', 'success')

    if login_key:
        return redirect(url_for('login', admin_key=login_key))

    return redirect(url_for('login'))


from flask_wtf.csrf import generate_csrf

_FOLDER_ACTION_MAP = {
    'pages.edit': 'edit',
    'pages.create': 'create',
    'pages.delete': 'delete',
    'pages.details': 'details',
    'pages.publish': 'publish',
    'pages.templates': 'template',
}


@app.context_processor
def inject_permissions_context():
    """Make permission helpers available in every template."""

    def _uperm(key):
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        if current_user.has_permission(key):
            return True
        _draft = _is_draft_context()
        if (_draft
                and key in _DRAFT_EDIT_COVERS
                and current_user.has_permission('website.draft.edit')):
            return True
        if (_draft
                and key in _DRAFT_PAGES_COVERS
                and current_user.has_permission('website.draft.pages')):
            return True
        return False

    def _uperm_for(key, website_obj=None):
        """Website-aware variant — pass the website object so checks in
        templates like the dashboard (which have no URL context) can still
        grant draft permissions correctly."""
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        if current_user.has_permission(key):
            return True
        if website_obj is not None and website_obj.is_draft:
            if (key in _DRAFT_EDIT_COVERS
                    and current_user.has_permission('website.draft.edit')):
                return True
            if (key in _DRAFT_PAGES_COVERS
                    and current_user.has_permission('website.draft.pages')):
                return True
        return False

    def _upage(page_id):
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        return can_access_page(page_id)

    def _upage_for(page_id, website_obj=None):
        """Website-aware page access check — draft.edit grants access to all
        draft pages without needing per-page ID grants."""
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        if (website_obj is not None
                and website_obj.is_draft
                and current_user.has_permission('website.draft.edit')):
            return True
        return can_access_page(page_id)

    def _usection(section_id):
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        return can_access_section(section_id)

    def _ufolder(folder_id):
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        return can_access_folder(folder_id)

    def _uhas_page_action(page, action_key, website_obj=None):
        """Return True if user has global perm for action_key OR has the
        corresponding folder-level perm for this page's folder."""
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        if _uperm_for(action_key, website_obj):
            return True
        folder_action = _FOLDER_ACTION_MAP.get(action_key)
        if folder_action and page is not None:
            return _folder_perm(getattr(page, 'page_folder_id', None), folder_action)
        return False

    def _uhas_folder_create(folder_id, website_obj=None):
        """Return True if user can create pages inside a specific page folder."""
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        if _uperm_for('pages.create', website_obj):
            return True
        return _folder_perm(folder_id, 'create')

    def _uhas_root_create(website_obj=None):
        """Return True if user can create root-level pages (outside any folder)."""
        if not current_user.is_authenticated or not current_user.is_sub_admin:
            return True
        return (_uperm_for('pages.create', website_obj)
                or _uperm_for('pages.create_root', website_obj))

    return dict(
        user_has_perm=_uperm,
        user_has_perm_for=_uperm_for,
        user_can_access_page=_upage,
        user_can_access_page_for=_upage_for,
        user_can_access_section=_usection,
        user_can_access_folder=_ufolder,
        user_has_page_action=_uhas_page_action,
        user_has_folder_create=_uhas_folder_create,
        user_has_root_create=_uhas_root_create,
        current_user_is_sub_admin=current_user.is_sub_admin if current_user.is_authenticated else False,
    )


@app.context_processor
def inject_current_website():
    if not current_user.is_authenticated:
        return {
            'current_website': None,
            'current_website_pages': [],
            'current_website_folders': [],
        }

    website = get_admin_website()

    if not website:
        return {
            'current_website': None,
            'current_website_pages': [],
            'current_website_folders': [],
        }

    pages = PublicPageContent.query.filter_by(website_id=website.id) \
        .order_by(PublicPageContent.id).all()

    folders = PageFolder.query.filter_by(website_id=website.id) \
        .order_by(PageFolder.sort_order, PageFolder.id).all()

    return {
        'current_website': website,
        'current_website_pages': pages,
        'current_website_folders': folders,
    }


@app.route('/admin/dashboard')
@login_required
def dashboard():
    user = current_user

    # Sub-admins share the root admin's website — never show the create-website screen to them
    if user.is_sub_admin:
        root = User.query.get(user.root_user_id)
        websites = root.websites if root else []
    else:
        websites = user.websites

    live_websites = [w for w in websites if not w.is_draft]
    draft_websites = [w for w in websites if w.is_draft]

    # Logic: If they have at least one live site, has_site is True
    has_site = len(live_websites) > 0

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

    # Build editor username lookup for last_edited_by_id across all pages
    all_pages = [p for pages in website_pages.values() for p in pages]
    editor_ids = {p.last_edited_by_id for p in all_pages if p.last_edited_by_id}
    page_editor_names = {}
    if editor_ids:
        editors = User.query.filter(User.id.in_(editor_ids)).all()
        page_editor_names = {u.id: u.username for u in editors}

    return render_template(
        'dashboard.html',
        websites=websites,
        live_websites=live_websites,
        draft_websites=draft_websites,
        website_pages=website_pages,
        website_page_groups=website_page_groups,
        website_page_folders=website_page_folders,
        user_has_website=has_site,
        csrf_token=csrf_token,
        email_settings=email_settings,
        page_editor_names=page_editor_names,
    )


@app.route('/create_page_folder/<int:website_id>', methods=['POST'])
@login_required
@require_perm('pages.create_folder')
def create_page_folder(website_id):
    website = Website.query.filter_by(
        id=website_id,
        user_id=current_user.root_user_id
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
        user_id=current_user.root_user_id
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
@require_perm('pages.reorder')
def move_page_to_folder(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    website = Website.query.filter_by(
        id=page.website_id,
        user_id=current_user.root_user_id
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
@require_perm('pages.delete_folder')
def delete_page_folder(folder_id):
    folder = PageFolder.query.get_or_404(folder_id)
    website = Website.query.filter_by(
        id=folder.website_id,
        user_id=current_user.root_user_id
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
@require_perm('pages.reorder')
def reorder_pages(website_id):
    website = Website.query.filter_by(
        id=website_id,
        user_id=current_user.root_user_id
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


def get_email_settings_fingerprint(settings):
    """
    Used to detect whether SMTP settings changed after 2FA was activated.
    Do not include smtp_password in a way that reveals it. We hash the combined config.
    """
    if not settings:
        return None

    raw = "|".join([
        settings.smtp_host or '',
        str(settings.smtp_port or ''),
        settings.smtp_username or '',
        settings.smtp_password or '',
        settings.from_email or '',
        settings.from_name or '',
        str(bool(settings.use_tls)),
        str(bool(settings.use_ssl)),
        str(bool(settings.is_active)),
    ])

    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def generate_two_factor_code():
    return f"{secrets.randbelow(1000000):06d}"


def _stamp_login(user):
    """Record login time and refresh last_seen_at."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user.last_login_at = now
    user.last_seen_at  = now
    db.session.commit()


def set_pending_two_factor_code(user_id, code, purpose):
    session['pending_2fa_user_id'] = user_id
    session['pending_2fa_code_hash'] = generate_password_hash(code)
    session['pending_2fa_purpose'] = purpose
    session['pending_2fa_expires_at'] = (
            datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=10)
    ).isoformat()
    # Stamp the send time on the User row so the cooldown is per-user, not per-session.
    user = User.query.get(user_id)
    if user:
        user.two_factor_last_sent_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()


def _2fa_recently_sent(user_id, cooldown_seconds=30):
    """Return True if a 2FA code was already sent for this user within the
    cooldown window.  Checked against the database so it is per-user and
    independent of which browser/session submitted the login form."""
    user = User.query.get(user_id)
    if not user or not user.two_factor_last_sent_at:
        return False
    elapsed = (datetime.now(timezone.utc).replace(tzinfo=None) - user.two_factor_last_sent_at).total_seconds()
    return elapsed < cooldown_seconds


def get_pending_two_factor_error(user_id, purpose):
    if session.get('pending_2fa_user_id') != user_id:
        return 'No matching verification code is pending.'

    if session.get('pending_2fa_purpose') != purpose:
        return 'This verification code is not valid for this action.'

    expires_raw = session.get('pending_2fa_expires_at')

    if not expires_raw:
        return 'This verification code expired.'

    try:
        expires_at = datetime.fromisoformat(expires_raw)
    except ValueError:
        return 'This verification code expired.'

    if datetime.now(timezone.utc).replace(tzinfo=None) > expires_at:
        return 'This verification code expired.'

    return None


def clear_pending_two_factor_code():
    session.pop('pending_2fa_user_id', None)
    session.pop('pending_2fa_code_hash', None)
    session.pop('pending_2fa_purpose', None)
    session.pop('pending_2fa_expires_at', None)


def send_two_factor_email(to_email, code, purpose='login'):
    settings = get_email_settings()

    if not settings or not settings.is_active:
        raise RuntimeError('Email server is not configured or active.')

    if not settings.smtp_host or not settings.smtp_port or not settings.smtp_username or not settings.smtp_password or not settings.from_email:
        raise RuntimeError('Email server settings are incomplete.')

    if settings.use_tls and settings.use_ssl:
        raise RuntimeError('Email server cannot use both TLS and SSL.')

    subject = 'Your Uwebia verification code'

    if purpose == 'activation':
        intro = 'Use this code to activate two-factor authentication for your Uwebia admin account.'
    else:
        intro = 'Use this code to finish logging in to your Uwebia admin account.'

    body = f"""{intro}

Verification code: {code}

This code expires in 10 minutes.

If you did not request this, you can ignore this email.
"""

    msg = MIMEMultipart()
    msg['From'] = (
        f"{settings.from_name} <{settings.from_email}>"
        if settings.from_name else settings.from_email
    )
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    if settings.use_ssl:
        server = smtplib.SMTP_SSL(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10
        )
    else:
        server = smtplib.SMTP(
            settings.smtp_host,
            settings.smtp_port,
            timeout=10
        )

        if settings.use_tls:
            server.starttls()

    try:
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)
    finally:
        server.quit()


@app.route('/admin/dashboard/settings/2fa/start', methods=['POST'])
@login_required
def start_two_factor_activation():
    email_settings = get_email_settings()

    if not email_settings or not email_settings.is_active:
        return jsonify({
            'status': 'error',
            'message': 'Email server settings must be saved and active before enabling 2FA.'
        }), 400

    two_factor_email = request.form.get('two_factor_email', '').strip().lower()

    if not two_factor_email:
        two_factor_email = current_user.email

    code = generate_two_factor_code()
    set_pending_two_factor_code(current_user.id, code, 'activation')

    print("")
    print("========================================")
    print("UWEBIA 2FA ACTIVATION CODE")
    print(f"User: {current_user.username}")
    print(f"Email: {two_factor_email}")
    print(f"Code: {code}")
    print("Expires in 10 minutes")
    print("========================================")
    print("")

    try:
        send_two_factor_email(two_factor_email, code, purpose='activation')
    except Exception as e:
        clear_pending_two_factor_code()

        return jsonify({
            'status': 'error',
            'message': f'Could not send 2FA activation email: {str(e)}'
        }), 400

    session['pending_2fa_email'] = two_factor_email

    return jsonify({
        'status': 'success',
        'message': f'Activation code sent to {two_factor_email}. Enter the code to enable 2FA.'
    })


@app.route('/admin/dashboard/settings/2fa/confirm', methods=['POST'])
@login_required
def confirm_two_factor_activation():
    code = request.form.get('code', '').strip()

    if not code:
        return jsonify({
            'status': 'error',
            'message': 'Please enter the activation code.'
        }), 400

    pending_error = get_pending_two_factor_error(current_user.id, 'activation')

    if pending_error:
        clear_pending_two_factor_code()
        return jsonify({
            'status': 'error',
            'message': pending_error
        }), 400

    expected_hash = session.get('pending_2fa_code_hash')

    if not expected_hash or not check_password_hash(expected_hash, code):
        return jsonify({
            'status': 'error',
            'message': 'Invalid activation code.'
        }), 400

    email_settings = get_email_settings()
    fingerprint = get_email_settings_fingerprint(email_settings)

    current_user.two_factor_enabled = True
    current_user.two_factor_email = session.get('pending_2fa_email') or current_user.email
    current_user.two_factor_activated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    current_user.two_factor_last_email_settings_version = fingerprint
    current_user.two_factor_disabled_reason = None
    current_user.two_factor_disabled_at = None
    current_user.two_factor_needs_attention = False

    db.session.commit()
    clear_pending_two_factor_code()
    session.pop('pending_2fa_email', None)

    return jsonify({
        'status': 'success',
        'message': 'Two-factor authentication is now enabled.'
    })


@app.route('/admin/dashboard/settings/2fa/disable', methods=['POST'])
@login_required
def disable_two_factor_authentication():
    disable_user_2fa(
        current_user,
        reason='you manually disabled it',
        needs_attention=False
    )
    current_user.two_factor_disabled_reason = None
    current_user.two_factor_disabled_at = None
    current_user.two_factor_needs_attention = False

    db.session.commit()
    clear_pending_two_factor_code()
    session.pop('pending_2fa_email', None)

    return jsonify({
        'status': 'success',
        'message': 'Two-factor authentication has been disabled.'
    })


@app.route('/admin/email_server_settings')
@login_required
def email_server_settings():
    user = current_user
    csrf_token = generate_csrf()

    email_settings = get_email_settings()

    return render_template(
        'email_server_settings.html',
        csrf_token=csrf_token,
        email_settings=email_settings,
        two_factor_enabled=current_user.two_factor_enabled
    )


def get_email_settings():
    return EmailServerSettings.query.first()


@app.route('/save_email_settings', methods=['POST'])
@login_required
def save_email_settings():
    settings = EmailServerSettings.query.first()
    old_fingerprint = get_email_settings_fingerprint(settings) if settings else None

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

    new_fingerprint = get_email_settings_fingerprint(settings)

    two_factor_disabled = False

    if old_fingerprint and old_fingerprint != new_fingerprint:
        users_with_2fa = User.query.filter_by(two_factor_enabled=True).all()

        for user in users_with_2fa:
            disable_user_2fa(
                user,
                reason='email server settings changed',
                needs_attention=True
            )

        db.session.commit()
        two_factor_disabled = len(users_with_2fa) > 0

    return jsonify({
        'status': 'success',
        'message': (
            'Email settings saved successfully. 2FA was disabled because email server settings changed.'
            if two_factor_disabled
            else 'Email settings saved successfully.'
        ),
        'two_factor_disabled': two_factor_disabled
    })


@app.route('/admin/dashboard/messages')
@login_required
@require_perm('messages.view')
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


@app.route('/admin/dashboard/messages/<int:message_id>/read', methods=['POST'])
@login_required
def mark_message_read(message_id):
    msg = ContactMessage.query.get_or_404(message_id)

    if not msg.is_read:
        msg.is_read = True
        msg.read_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/admin/dashboard/messages/<int:message_id>/unread', methods=['POST'])
@login_required
def mark_message_unread(message_id):
    msg = ContactMessage.query.get_or_404(message_id)

    msg.is_read = False
    msg.read_at = None
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/admin/dashboard/messages/unread_count')
@login_required
def unread_messages_count():
    count = ContactMessage.query.filter_by(is_read=False).count()
    return jsonify({'count': count})


@app.route('/admin/dashboard/messages/live')
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


@app.route('/admin/dashboard/messages/<int:message_id>/delete', methods=['POST'])
@login_required
@require_perm('messages.delete')
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

    section = PageSection.query.get(section_id)
    if not section or section.section_type != 'contact_form':
        return jsonify({
            'status': 'error',
            'message': 'Invalid contact form section'
        }), 404

    recipient_email = None
    contact_form_title = None

    if section.content and isinstance(section.content, dict):
        recipient_email = (section.content.get('email') or '').strip()
        contact_form_title = section.content.get('title')

    page_id = getattr(section, 'page_content_id', None)
    website_id = None

    if section.public_page_content:
        website_id = section.public_page_content.website_id

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

    user_agent = request.headers.get('User-Agent')
    referrer = request.referrer

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
        status='stored'
    )

    db.session.add(contact_message)
    db.session.commit()

    email_settings = get_email_settings()

    # Important:
    # If SMTP is not configured, still treat the public form submission as successful
    # because the message has already been saved in the admin inbox.
    if not email_settings or not email_settings.is_active:
        contact_message.status = 'stored'
        contact_message.error_message = 'Email server is not configured. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message sent successfully.'
        })

    if not recipient_email:
        contact_message.status = 'stored'
        contact_message.error_message = 'No recipient email found for this contact form. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    if (
            not email_settings.smtp_host
            or not email_settings.smtp_port
            or not email_settings.smtp_username
            or not email_settings.smtp_password
            or not email_settings.from_email
    ):
        contact_message.status = 'stored'
        contact_message.error_message = 'Email server settings are incomplete. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    if email_settings.use_tls and email_settings.use_ssl:
        contact_message.status = 'stored'
        contact_message.error_message = 'Email server cannot use both TLS and SSL. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    formatted_body = f"""You have received a new message from your Uwebia website contact form.

Sender Email: {sender_email}
Subject: {subject}

Message Body:
{body}

---
Contact Form: {contact_form_title or ''}
IP Address: {ip_address or ''}
Referrer: {referrer or ''}
"""

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

        try:
            server.login(email_settings.smtp_username, email_settings.smtp_password)
            server.send_message(msg)
        finally:
            server.quit()

        contact_message.status = 'sent'
        contact_message.sent_at = datetime.now(timezone.utc).replace(tzinfo=None)
        contact_message.error_message = None
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except smtplib.SMTPAuthenticationError:
        contact_message.status = 'stored'
        contact_message.error_message = 'Email login failed. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except smtplib.SMTPConnectError:
        contact_message.status = 'stored'
        contact_message.error_message = 'Could not connect to the email server. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except smtplib.SMTPServerDisconnected:
        contact_message.status = 'stored'
        contact_message.error_message = 'The email server disconnected unexpectedly. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except smtplib.SMTPRecipientsRefused:
        contact_message.status = 'stored'
        contact_message.error_message = 'The recipient email address was refused. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except smtplib.SMTPException as e:
        contact_message.status = 'stored'
        contact_message.error_message = f'Email sending failed: {str(e)}. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except ssl.SSLError:
        contact_message.status = 'stored'
        contact_message.error_message = 'SSL/TLS handshake failed. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })

    except Exception as e:
        import traceback
        traceback.print_exc()

        contact_message.status = 'stored'
        contact_message.error_message = f'Unexpected email error: {str(e)}. Message was saved to the admin inbox only.'
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Message received successfully.'
        })


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
    existing_site = get_admin_website()

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


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'orange-uw.svg', mimetype='image/svg+xml')


def get_live_website():
    """Return the single live (non-draft) website. Used by all public routes so
    draft websites are never accidentally served to visitors."""
    return Website.query.filter_by(is_draft=False).first()


@app.route('/<string:page_slug>')
def public_page_by_slug(page_slug):
    website = get_live_website()

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
    if not is_owner(website):
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})
    if current_user.is_sub_admin:
        _raw = ((request.get_json() or {}).get('folder_id') if request.is_json
                else request.form.get('folder_id', ''))
        try:
            _perm_folder_id = int(_raw) if _raw else None
        except (ValueError, TypeError):
            _perm_folder_id = None

        if _perm_folder_id is not None:
            # Creating inside a folder — requires global pages.create or folder-level create perm
            if not (current_user.has_permission('pages.create')
                    or _folder_perm(_perm_folder_id, 'create')):
                return jsonify({'status': 'error', 'message': 'Permission denied'}), 403
        else:
            # Creating at root level — requires pages.create_root (or the legacy pages.create)
            if not (current_user.has_permission('pages.create_root')
                    or current_user.has_permission('pages.create')):
                return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    if request.method == 'POST':
        # Handle form submission to create a new page
        name = request.form['name']
        description = request.form['description']
        tags = request.form.get('tags', '')  # Get tags from the form, default to empty string if not provided
        post_folder_id = request.form.get('folder_id') or None
        if post_folder_id:
            try:
                post_folder_id = int(post_folder_id)
            except (ValueError, TypeError):
                post_folder_id = None

        new_content = PublicPageContent(name=name, description=description, website_id=website_id,
                                        slug=get_unique_slug(website_id, name),
                                        page_folder_id=post_folder_id)
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
@require_perm('website.edit')
def edit_website(website_id):
    website = Website.query.get_or_404(website_id)

    if not is_owner(website):
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

    if not is_owner(website):
        return jsonify({
            'success': False,
            'message': 'Unauthorized access'
        }), 403

    data = request.get_json()

    website.background_color = data.get('background_color', website.background_color)
    website.text_color = data.get('text_color', website.text_color)

    website.background_image_url = data.get('background_image_url') or None
    website.background_image_repeat = bool(data.get('background_image_repeat', False))
    website.background_image_repeat_x = bool(data.get('background_image_repeat_x', False))
    website.background_image_mobile_cover = bool(data.get('background_image_mobile_cover', False))

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
        'background_image_repeat_x': website.background_image_repeat_x,
        'background_image_mobile_cover': website.background_image_mobile_cover,
        'background_image_zoom': website.background_image_zoom
    })


@app.route('/edit_page/<int:website_id>/<int:page_id>', methods=['POST'])
@login_required
def edit_page(website_id, page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    if current_user.is_sub_admin:
        if not (current_user.has_permission('pages.details')
                or _folder_perm(page.page_folder_id, 'details')):
            return jsonify({'error': 'Permission denied'}), 403
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


def copy_section_links_and_events(old_section, new_section):
    """
    Copies section relationships that live outside PageSection.content.

    New system:
    - SectionAsset -> Asset

    Legacy compatibility:
    - SectionImage -> Picture

    Calendar:
    - CalendarEvent
    """

    # New asset-library section links
    source_assets = SectionAsset.query.filter_by(
        section_id=old_section.id
    ).order_by(SectionAsset.order).all()

    for old_link in source_assets:
        db.session.add(SectionAsset(
            section_id=new_section.id,
            asset_id=old_link.asset_id,
            usage_type=old_link.usage_type,
            order=old_link.order
        ))

    # Legacy image-library links, safe to keep for old pages/data
    source_images = SectionImage.query.filter_by(
        section_id=old_section.id
    ).order_by(SectionImage.order).all()

    for old_img in source_images:
        db.session.add(SectionImage(
            section_id=new_section.id,
            picture_id=old_img.picture_id,
            order=old_img.order
        ))

    # Calendar events
    source_events = CalendarEvent.query.filter_by(
        section_id=old_section.id
    ).all()

    for old_event in source_events:
        db.session.add(CalendarEvent(
            title=old_event.title,
            description=old_event.description,
            start=old_event.start,
            end=old_event.end,
            background_color=old_event.background_color,
            section_id=new_section.id
        ))


def copy_section_group(old_group, new_page_id):
    return SectionGroup(
        page_content_id=new_page_id,
        name=old_group.name,
        anchor_slug=old_group.anchor_slug,
        group_order=old_group.group_order,

        background_color=old_group.background_color,
        background_opacity=old_group.background_opacity,
        padding=old_group.padding,
        border_radius=old_group.border_radius,
        max_width=old_group.max_width,

        background_image_url=old_group.background_image_url,
        background_image_size=old_group.background_image_size,
        background_image_position=old_group.background_image_position,
        background_overlay_color=old_group.background_overlay_color,
        background_overlay_opacity=old_group.background_overlay_opacity
    )


@app.route('/duplicate_page/<int:website_id>/<int:page_id>', methods=['POST'])
@login_required
def duplicate_page(website_id, page_id):
    try:
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user.id
        ).first_or_404()

        original_page = PublicPageContent.query.filter_by(
            id=page_id,
            website_id=website.id
        ).first_or_404()

        if current_user.is_sub_admin:
            if not (current_user.has_permission('pages.create')
                    or _folder_perm(original_page.page_folder_id, 'duplicate')):
                return jsonify({'error': 'Permission denied'}), 403

        copy_name = get_copy_name(original_page.website_id, original_page.name)

        new_page = PublicPageContent(
            website_id=original_page.website_id,
            page_folder_id=original_page.page_folder_id,
            folder_sort_order=original_page.folder_sort_order,
            sort_order=(original_page.sort_order or 0) + 1,

            name=copy_name,
            description=original_page.description,
            site_active_status=False,

            background_color=original_page.background_color,
            text_color=original_page.text_color,

            slug=get_unique_slug(original_page.website_id, copy_name)
        )

        db.session.add(new_page)
        db.session.flush()

        # Copy tags
        for tag in original_page.tags:
            new_page.tags.append(tag)

        # Copy groups
        group_map = {}

        original_groups = SectionGroup.query.filter_by(
            page_content_id=original_page.id
        ).order_by(SectionGroup.group_order, SectionGroup.id).all()

        for old_group in original_groups:
            new_group = copy_section_group(old_group, new_page.id)

            db.session.add(new_group)
            db.session.flush()

            group_map[old_group.id] = new_group.id

        # Copy sections
        section_map = {}

        original_sections = PageSection.query.filter_by(
            page_content_id=original_page.id
        ).order_by(PageSection.order, PageSection.id).all()

        for old_section in original_sections:
            new_section = PageSection(
                section_type=old_section.section_type,
                order=old_section.order,
                content=copy.deepcopy(old_section.content or {}),
                page_content_id=new_page.id
            )

            db.session.add(new_section)
            db.session.flush()

            section_map[old_section.id] = new_section.id

            copy_section_links_and_events(old_section, new_section)

        # Copy rows and columns
        original_rows = Row.query.filter_by(
            page_content_id=original_page.id
        ).order_by(Row.row_number, Row.id).all()

        for old_row in original_rows:
            new_row = Row(
                page_content_id=new_page.id,
                row_number=old_row.row_number,
                section_group_id=(
                    group_map.get(old_row.section_group_id)
                    if old_row.section_group_id
                    else None
                )
            )

            db.session.add(new_row)
            db.session.flush()

            original_columns = Column.query.filter_by(
                row_id=old_row.id
            ).order_by(Column.column_number, Column.id).all()

            for old_column in original_columns:
                db.session.add(Column(
                    row_id=new_row.id,
                    column_number=old_column.column_number,
                    width=old_column.width,
                    section_id=(
                        section_map.get(old_column.section_id)
                        if old_column.section_id
                        else None
                    )
                ))

        db.session.commit()

        return jsonify({
            'success': True,
            'page_id': new_page.id,
            'page_name': new_page.name,
            'slug': new_page.slug
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error duplicating page: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def _serialize_page(page):
    """Serialize a full page layout to a dict for use as a template."""
    groups = SectionGroup.query.filter_by(
        page_content_id=page.id
    ).order_by(SectionGroup.group_order).all()

    all_rows = Row.query.filter_by(
        page_content_id=page.id
    ).order_by(Row.row_number).all()

    def _serialize_rows(row_list):
        result, count = [], 0
        for row in row_list:
            cols = Column.query.filter_by(row_id=row.id).order_by(Column.column_number).all()
            cols_data = []
            for col in cols:
                s = col.section
                cols_data.append({
                    'column_number': col.column_number,
                    'width': col.width,
                    'section': {'section_type': s.section_type, 'content': s.content} if s else None,
                })
                if s:
                    count += 1
            result.append({'columns': cols_data})
        return result, count

    groups_data = []
    total_sections = 0
    for group in groups:
        grp_rows = [r for r in all_rows if r.section_group_id == group.id]
        rows_data, sc = _serialize_rows(grp_rows)
        total_sections += sc
        groups_data.append({
            'name': group.name,
            'styles': {
                'background_color': group.background_color or 'transparent',
                'background_opacity': group.background_opacity or 1,
                'padding': group.padding or 0,
                'border_radius': group.border_radius or 0,
                'max_width': group.max_width,
                'background_image_url': group.background_image_url,
                'background_image_size': group.background_image_size or 'cover',
                'background_image_position': group.background_image_position or 'center',
                'background_overlay_color': group.background_overlay_color or 'transparent',
                'background_overlay_opacity': group.background_overlay_opacity or 0,
            },
            'rows': rows_data,
        })

    ungrouped_rows = [r for r in all_rows if r.section_group_id is None]
    ungrouped_data, sc2 = _serialize_rows(ungrouped_rows)
    total_sections += sc2

    return {
        'page_style': {
            'background_color': page.background_color or '#ffffff',
            'text_color': page.text_color or '#000000',
        },
        'groups': groups_data,
        'ungrouped_rows': ungrouped_data,
    }, len(groups), total_sections


def _instantiate_page_template(website_id, template_data, name, description='', tags_str=''):
    """Create a new page from serialized page template data."""
    slug = get_unique_slug(website_id, name)
    page_style = template_data.get('page_style', {})

    new_page = PublicPageContent(
        name=name,
        description=description or None,
        website_id=website_id,
        slug=slug,
        site_active_status=False,
        background_color=page_style.get('background_color', '#ffffff'),
        text_color=page_style.get('text_color', '#000000'),
    )
    db.session.add(new_page)
    db.session.flush()

    if tags_str:
        for tag_name in [t.strip() for t in tags_str.split(',') if t.strip()]:
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.session.add(tag)
                db.session.flush()
            new_page.tags.append(tag)

    max_row = 0

    def _create_rows(rows_data, group_id=None):
        nonlocal max_row
        for row_data in rows_data:
            max_row += 1
            new_row = Row(
                page_content_id=new_page.id,
                row_number=max_row,
                section_group_id=group_id,
            )
            db.session.add(new_row)
            db.session.flush()
            for col_data in row_data.get('columns', []):
                s_data = col_data.get('section')
                new_section = None
                if s_data:
                    new_section = PageSection(
                        section_type=s_data['section_type'],
                        content=s_data.get('content'),
                        order=col_data['column_number'],
                        page_content_id=new_page.id,
                    )
                    db.session.add(new_section)
                    db.session.flush()
                db.session.add(Column(
                    row_id=new_row.id,
                    column_number=col_data['column_number'],
                    width=col_data.get('width', 100),
                    section_id=new_section.id if new_section else None,
                ))

    for grp_idx, grp_data in enumerate(template_data.get('groups', [])):
        styles = grp_data.get('styles', {})
        new_group = SectionGroup(
            page_content_id=new_page.id,
            name=grp_data.get('name', 'Section Group'),
            group_order=grp_idx + 1,
            background_color=styles.get('background_color', 'transparent'),
            background_opacity=styles.get('background_opacity', 1),
            padding=styles.get('padding', 0),
            border_radius=styles.get('border_radius', 0),
            max_width=styles.get('max_width'),
            background_image_url=styles.get('background_image_url'),
            background_image_size=styles.get('background_image_size', 'cover'),
            background_image_position=styles.get('background_image_position', 'center'),
            background_overlay_color=styles.get('background_overlay_color', 'transparent'),
            background_overlay_opacity=styles.get('background_overlay_opacity', 0),
        )
        db.session.add(new_group)
        db.session.flush()
        _create_rows(grp_data.get('rows', []), group_id=new_group.id)

    _create_rows(template_data.get('ungrouped_rows', []))

    db.session.commit()
    return new_page


@app.route('/admin/page_templates', methods=['GET'])
@login_required
def list_page_templates():
    website = get_admin_website()
    if not website:
        return jsonify({'templates': []})
    templates = PageTemplate.query.filter_by(website_id=website.id).order_by(
        PageTemplate.created_at.desc()
    ).all()
    return jsonify({'templates': [t.to_dict() for t in templates]})


@app.route('/admin/page_templates/save/<int:page_id>', methods=['POST'])
@login_required
def save_page_template(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    if current_user.is_sub_admin:
        if not (current_user.has_permission('pages.templates')
                or _folder_perm(page.page_folder_id, 'template')):
            return jsonify({'success': False, 'error': 'Permission denied'}), 403

    data = request.get_json()
    name = (data.get('name') or page.name or 'Template').strip()

    template_data, group_count, section_count = _serialize_page(page)
    tmpl = PageTemplate(
        website_id=website.id,
        name=name,
        description=(data.get('description') or '').strip() or None,
        template_data=template_data,
        group_count=group_count,
        section_count=section_count,
    )
    db.session.add(tmpl)
    db.session.commit()
    return jsonify({'success': True, 'template': tmpl.to_dict()}), 201


@app.route('/admin/page_templates/<int:template_id>/delete', methods=['POST'])
@login_required
@require_perm('pages.templates')
def delete_page_template(template_id):
    tmpl = PageTemplate.query.get_or_404(template_id)
    if Website.query.get_or_404(tmpl.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    db.session.delete(tmpl)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/create_page_from_template/<int:website_id>/<int:template_id>', methods=['POST'])
@login_required
def create_page_from_template(website_id, template_id):
    website = Website.query.filter_by(id=website_id, user_id=current_user.root_user_id).first_or_404()
    tmpl = PageTemplate.query.get_or_404(template_id)
    if tmpl.website_id != website.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    if current_user.is_sub_admin:
        if not current_user.has_permission('pages.templates'):
            data_pre = request.get_json(silent=True) or {}
            folder_id = data_pre.get('folder_id')
            if folder_id:
                if not _folder_perm(folder_id, 'template'):
                    return jsonify({'success': False, 'error': 'Permission denied'}), 403
            else:
                # Root-level template creation requires pages.create_root or pages.create
                if not (current_user.has_permission('pages.create_root')
                        or current_user.has_permission('pages.create')):
                    return jsonify({'success': False, 'error': 'Permission denied'}), 403

    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Page name is required'}), 400

    try:
        new_page = _instantiate_page_template(
            website_id=website.id,
            template_data=tmpl.template_data,
            name=name,
            description=data.get('description', ''),
            tags_str=data.get('tags', ''),
        )
        return jsonify({
            'success': True,
            'page_id': new_page.id,
            'editor_url': url_for('page_editor', website_id=website.id, page_id=new_page.id),
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/replace_page/<int:target_page_id>/<int:source_page_id>', methods=['POST'])
@login_required
def replace_page(target_page_id, source_page_id):
    try:
        target_page = PublicPageContent.query.get_or_404(target_page_id)
        source_page = PublicPageContent.query.get_or_404(source_page_id)

        target_website = Website.query.get_or_404(target_page.website_id)
        source_website = Website.query.get_or_404(source_page.website_id)

        if not is_owner(target_website) or not is_owner(source_website):
            return jsonify({"success": False, "error": "Unauthorized"}), 403

        if target_page.id == source_page.id:
            return jsonify({
                "success": False,
                "error": "Cannot replace a page with itself."
            }), 400

        # Keep target identity/url fields.
        # Do not overwrite target_page.name, target_page.slug, or target_page.site_active_status.
        target_page.description = source_page.description
        target_page.background_color = source_page.background_color
        target_page.text_color = source_page.text_color

        # Replace tags
        target_page.tags.clear()
        for tag in source_page.tags:
            target_page.tags.append(tag)

        # Delete existing target sections and dependent relationships first.
        old_target_sections = PageSection.query.filter_by(
            page_content_id=target_page.id
        ).all()

        for section in old_target_sections:
            SectionAsset.query.filter_by(section_id=section.id).delete()
            SectionImage.query.filter_by(section_id=section.id).delete()
            CalendarEvent.query.filter(
                CalendarEvent.section_id == section.id,
                CalendarEvent.calendar_id == None
            ).delete()
            db.session.delete(section)

        db.session.flush()

        # Delete rows/columns and groups after sections.
        # Columns are delete-orphan through Row.columns, so deleting Row removes Columns.
        Row.query.filter_by(page_content_id=target_page.id).delete()
        SectionGroup.query.filter_by(page_content_id=target_page.id).delete()

        db.session.flush()

        # Copy source groups
        group_map = {}

        source_groups = SectionGroup.query.filter_by(
            page_content_id=source_page.id
        ).order_by(SectionGroup.group_order, SectionGroup.id).all()

        for old_group in source_groups:
            new_group = copy_section_group(old_group, target_page.id)

            db.session.add(new_group)
            db.session.flush()

            group_map[old_group.id] = new_group.id

        # Copy source sections
        section_map = {}

        source_sections = PageSection.query.filter_by(
            page_content_id=source_page.id
        ).order_by(PageSection.order, PageSection.id).all()

        for old_section in source_sections:
            new_section = PageSection(
                section_type=old_section.section_type,
                order=old_section.order,
                content=copy.deepcopy(old_section.content or {}),
                page_content_id=target_page.id
            )

            db.session.add(new_section)
            db.session.flush()

            section_map[old_section.id] = new_section.id

            copy_section_links_and_events(old_section, new_section)

        # Copy source rows and columns
        source_rows = Row.query.filter_by(
            page_content_id=source_page.id
        ).order_by(Row.row_number, Row.id).all()

        for old_row in source_rows:
            new_row = Row(
                page_content_id=target_page.id,
                row_number=old_row.row_number,
                section_group_id=(
                    group_map.get(old_row.section_group_id)
                    if old_row.section_group_id
                    else None
                )
            )

            db.session.add(new_row)
            db.session.flush()

            source_columns = Column.query.filter_by(
                row_id=old_row.id
            ).order_by(Column.column_number, Column.id).all()

            for old_column in source_columns:
                db.session.add(Column(
                    row_id=new_row.id,
                    column_number=old_column.column_number,
                    width=old_column.width,
                    section_id=(
                        section_map.get(old_column.section_id)
                        if old_column.section_id
                        else None
                    )
                ))

        db.session.commit()

        return jsonify({
            "success": True,
            "target_page_id": target_page.id
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error replacing page: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


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
    if not is_owner(website):
        return jsonify({'status': 'error', 'message': 'Unauthorized access'})

    content = PublicPageContent.query.get_or_404(page_id)

    # Sub-admin page-level access check.
    # For live websites we enforce the per-page grant list OR a folder-level
    # edit perm; for draft websites full access is implied by website.draft.edit.
    if current_user.is_sub_admin:
        if website.is_draft:
            if not (current_user.has_permission('pages.edit')
                    or current_user.has_permission('website.draft.edit')):
                flash('You don\'t have permission to edit draft pages.', 'permission_denied')
                return redirect(url_for('dashboard'))
        else:
            has_edit = (current_user.has_permission('pages.edit')
                        or _folder_perm(content.page_folder_id, 'edit'))
            if not has_edit:
                flash(_perm_label('pages.edit') + ' — you don\'t have access to the page editor.', 'permission_denied')
                return redirect(url_for('dashboard'))
            if not (can_access_page(page_id)
                    or _folder_perm(content.page_folder_id, 'edit')):
                flash('You don\'t have access to this specific page. Ask your admin to grant access.',
                      'permission_denied')
                return redirect(url_for('dashboard'))
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

    ai_agents = AIAgent.query.filter_by(website_id=website.id).order_by(AIAgent.name).all()

    # Resolve accessible section and group IDs for sub-admins.
    # Page-level grant → null (all accessible). Otherwise merge explicit + derived grants.
    # For draft websites: website.draft.edit grants full access to all sections
    # and groups — live-website restrictions must not bleed into the draft.
    resolved_section_ids = None
    resolved_group_ids = None
    if current_user.is_sub_admin and not (
            website.is_draft and current_user.has_permission('website.draft.edit')):
        # Draft + draft.edit = full unrestricted access (null stays null).
        # All other cases: apply the per-page/section/group grant lists.
        perms = _effective_perms()
        allowed_sections = perms.get('sections.allowed_ids')
        allowed_groups = perms.get('groups.allowed_ids')
        allowed_pages = perms.get('pages.allowed_ids')
        if allowed_sections is not None or allowed_groups is not None or allowed_pages is not None:
            # Page-level grant covers everything on this page
            if allowed_pages is not None and page_id in allowed_pages:
                resolved_section_ids = None  # null = all sections unlocked
                resolved_group_ids = None  # null = all groups unlocked
            else:
                # Sections: union of direct grants + group-expanded grants
                sec_resolved = set(allowed_sections or [])
                # Groups: union of explicit grants + groups that contain a granted section
                grp_resolved = set(allowed_groups or [])
                for s in sections:
                    if s.column and s.column.row:
                        g_id = s.column.row.section_group_id
                        if g_id is not None:
                            if allowed_groups and g_id in allowed_groups:
                                sec_resolved.add(s.id)
                            if allowed_sections and s.id in allowed_sections:
                                grp_resolved.add(g_id)
                resolved_section_ids = list(sec_resolved)
                resolved_group_ids = list(grp_resolved)

    return render_template(
        'page_editor.html',
        site_active_status=site_active_status,
        sections=sections,
        page_id=page_id,
        website=website,
        page_content=content,
        navbar_pages=navbar_pages,
        ai_agents=ai_agents,
        resolved_section_ids=resolved_section_ids,
        resolved_group_ids=resolved_group_ids,
        is_draft_website=website.is_draft,
    )


@app.route('/delete_page/<int:website_id>/<int:page_id>', methods=['POST'])
@login_required
def delete_page(website_id, page_id):
    page = PublicPageContent.query.filter_by(id=page_id, website_id=website_id).first()
    if not page:
        return jsonify({'error': 'Page not found'}), 404
    if current_user.is_sub_admin:
        if not (current_user.has_permission('pages.delete')
                or _folder_perm(page.page_folder_id, 'delete')):
            return jsonify({'error': 'Permission denied'}), 403
    if page.slug == 'home':
        return jsonify({
            'error': 'The root page cannot be deleted. Use Replace Page to change its content or edit it directly.'
        }), 400
    website = Website.query.filter_by(id=website_id, user_id=current_user.root_user_id).first()
    if not website:
        return jsonify({'error': 'You are not authorized to delete this page'}), 403
    try:
        _delete_single_page(page)
        db.session.commit()
        return jsonify({'message': 'Page deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'delete_page {page_id} error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/delete_website/<int:website_id>', methods=['POST'])
@login_required
def delete_website(website_id):
    website = Website.query.filter_by(id=website_id, user_id=current_user.root_user_id).first()
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


def _delete_single_page(page):
    """Delete one page and all its FK-dependent records in leaf-to-root order."""
    _delete_website_pages_by_ids([page.id])


def _delete_website_pages_by_ids(page_ids):
    """Core FK-safe deletion for a list of page IDs and every record that
    references them or their child sections/rows."""
    if not page_ids:
        return

    db.session.execute(db.text("PRAGMA defer_foreign_keys=ON"))

    section_ids = [s.id for s in
                   PageSection.query.filter(
                       PageSection.page_content_id.in_(page_ids)).all()]

    if section_ids:
        SectionAsset.query.filter(
            SectionAsset.section_id.in_(section_ids)).delete(
            synchronize_session=False)
        SectionImage.query.filter(
            SectionImage.section_id.in_(section_ids)).delete(
            synchronize_session=False)
        PageCommentLike.query.filter(
            PageCommentLike.section_id.in_(section_ids)).delete(
            synchronize_session=False)
        PageComment.query.filter(
            PageComment.section_id.in_(section_ids)).delete(
            synchronize_session=False)
        CalendarFeedSubscriber.query.filter(
            CalendarFeedSubscriber.section_id.in_(section_ids)).delete(
            synchronize_session=False)
        db.session.query(CalendarEvent).filter(
            CalendarEvent.section_id.in_(section_ids)).update(
            {'section_id': None}, synchronize_session=False)

    row_ids = [r.id for r in
               Row.query.filter(Row.page_content_id.in_(page_ids)).all()]
    if row_ids:
        Column.query.filter(
            Column.row_id.in_(row_ids)).delete(synchronize_session=False)

    PageSection.query.filter(
        PageSection.page_content_id.in_(page_ids)).delete(
        synchronize_session=False)
    Row.query.filter(
        Row.page_content_id.in_(page_ids)).delete(synchronize_session=False)
    SectionGroup.query.filter(
        SectionGroup.page_content_id.in_(page_ids)).delete(
        synchronize_session=False)
    PageVisit.query.filter(
        PageVisit.page_id.in_(page_ids)).delete(synchronize_session=False)

    page_tag_table = db.metadata.tables['page_tag']
    db.session.execute(
        page_tag_table.delete().where(page_tag_table.c.page_id.in_(page_ids))
    )

    PublicPageContent.query.filter(
        PublicPageContent.id.in_(page_ids)).delete(synchronize_session=False)


def _delete_website_pages(website):
    """Delete all pages and folders belonging to *website* using the shared
    FK-safe core.  Caller is responsible for flush/commit."""
    page_ids = [p.id for p in website.public_page_contents]
    _delete_website_pages_by_ids(page_ids)
    PageFolder.query.filter_by(website_id=website.id).delete(
        synchronize_session=False)


def _delete_website_all(website):
    """Completely wipe a website and every record that FKs to it, then delete
    the website row itself — all using bulk deletes so SQLAlchemy's cascade
    logic never fires and double-delete warnings / FK violations are avoided.

    Call _delete_website_pages() first to handle page-tree records, then call
    this to handle website-level records and the website row."""
    wid = website.id

    # --- Page tree (pages, sections, rows, columns, groups, folders) ---
    _delete_website_pages(website)
    db.session.flush()

    # --- Website-level records (templates, agents, tags, forum, etc.) ---
    # Templates the user may have saved while editing the draft
    SectionGroupTemplate.query.filter_by(website_id=wid).delete(synchronize_session=False)
    SectionTemplate.query.filter_by(website_id=wid).delete(synchronize_session=False)
    PageTemplate.query.filter_by(website_id=wid).delete(synchronize_session=False)

    # AI agents
    AIAgent.query.filter_by(website_id=wid).delete(synchronize_session=False)

    # Calendars + their children
    cal_ids = [c.id for c in Calendar.query.filter_by(website_id=wid).all()]
    if cal_ids:
        CalendarFeedSubscriber.query.filter(
            CalendarFeedSubscriber.calendar_id.in_(cal_ids)).delete(synchronize_session=False)
        db.session.query(CalendarEvent).filter(
            CalendarEvent.calendar_id.in_(cal_ids)).delete(synchronize_session=False)
        CalendarSubscription.query.filter(
            CalendarSubscription.calendar_id.in_(cal_ids)).delete(synchronize_session=False)
        Calendar.query.filter_by(website_id=wid).delete(synchronize_session=False)

    # Forum (unlikely for a draft, but safe to include)
    ForumReplyVote.query.filter_by(website_id=wid).delete(synchronize_session=False)
    ForumThreadVote.query.filter_by(website_id=wid).delete(synchronize_session=False)
    ForumReply.query.filter_by(website_id=wid).delete(synchronize_session=False)
    ForumThread.query.filter_by(website_id=wid).delete(synchronize_session=False)

    # Comments / messages / users / visits
    PageCommentLike.query.filter_by(website_id=wid).delete(synchronize_session=False)
    PageComment.query.filter_by(website_id=wid).delete(synchronize_session=False)
    ContactMessage.query.filter_by(website_id=wid).delete(synchronize_session=False)
    PublicUser.query.filter_by(website_id=wid).delete(synchronize_session=False)
    PageVisit.query.filter_by(website_id=wid).delete(synchronize_session=False)

    # Website-tag association table (no ORM class)
    wt = db.metadata.tables.get('website_tag')
    if wt is not None:
        db.session.execute(wt.delete().where(wt.c.website_id == wid))

    db.session.flush()

    # Delete the website itself via bulk query to bypass SQLAlchemy's cascade
    # (which would re-issue DELETEs for already-deleted child rows and cause
    # "0 rows matched" warnings or FK errors at commit time).
    Website.query.filter_by(id=wid).delete(synchronize_session=False)
    db.session.flush()


def _copy_website_settings(source, target):
    """Copy all Website-level styling / config fields from source → target."""
    for field in [
        'name', 'description',
        'background_color', 'text_color', 'background_image_url',
        'background_image_repeat', 'background_image_repeat_x',
        'background_image_mobile_cover', 'background_image_zoom',
        'public_navbar_items', 'public_navbar_style',
        'forum_enabled', 'forum_show_in_navbar', 'forum_require_login_to_view',
        'forum_require_login_to_post', 'forum_title', 'forum_description',
        'forum_account_verification_enabled', 'forum_allow_unverified_login',
    ]:
        setattr(target, field, getattr(source, field))


def _copy_website_content(source_website, target_website):
    """Deep-copy all pages, sections, rows, columns, groups, and folders
    from source_website into target_website (which must already exist in the
    session). Does NOT touch forum data, analytics, messages, or calendars."""
    import json as _json

    # Expire all cached session objects so every attribute access below reads
    # fresh data from the DB.  Bulk deletes with synchronize_session=False
    # leave stale Python objects in the identity map; without expire_all those
    # stale objects could be returned by db.session.get() and carry wrong
    # (or missing) content/custom_code values into the copy.
    db.session.expire_all()

    # --- Folders ---
    folder_id_map = {}
    for folder in PageFolder.query.filter_by(
            website_id=source_website.id).order_by(PageFolder.sort_order, PageFolder.id).all():
        new_folder = PageFolder(
            website_id=target_website.id,
            name=folder.name,
            sort_order=folder.sort_order,
        )
        db.session.add(new_folder)
        db.session.flush()
        folder_id_map[folder.id] = new_folder.id

    # --- Pages ---
    for page in PublicPageContent.query.filter_by(
            website_id=source_website.id).order_by(
        PublicPageContent.sort_order, PublicPageContent.id).all():

        new_page = PublicPageContent(
            website_id=target_website.id,
            name=page.name,
            description=page.description,
            slug=page.slug,
            sort_order=page.sort_order,
            folder_sort_order=page.folder_sort_order,
            site_active_status=page.site_active_status,
            background_color=page.background_color,
            text_color=page.text_color,
            custom_code=page.custom_code,
            page_folder_id=folder_id_map.get(page.page_folder_id) if page.page_folder_id else None,
        )
        db.session.add(new_page)
        db.session.flush()

        # Section groups (must exist before rows reference them)
        group_id_map = {}
        for group in SectionGroup.query.filter_by(
                page_content_id=page.id).order_by(SectionGroup.group_order).all():
            new_group = SectionGroup(
                page_content_id=new_page.id,
                name=group.name,
                anchor_slug=group.anchor_slug,
                group_order=group.group_order,
                background_color=group.background_color,
                background_opacity=group.background_opacity,
                padding=group.padding,
                border_radius=group.border_radius,
                max_width=group.max_width,
                background_image_url=group.background_image_url,
                background_image_size=group.background_image_size,
                background_image_position=group.background_image_position,
                background_overlay_color=group.background_overlay_color,
                background_overlay_opacity=group.background_overlay_opacity,
            )
            db.session.add(new_group)
            db.session.flush()
            group_id_map[group.id] = new_group.id

        # Rows → Columns → Sections
        for row in Row.query.filter_by(
                page_content_id=page.id).order_by(Row.row_number).all():
            new_row = Row(
                page_content_id=new_page.id,
                row_number=row.row_number,
                section_group_id=group_id_map.get(row.section_group_id) if row.section_group_id else None,
            )
            db.session.add(new_row)
            db.session.flush()

            for col in Column.query.filter_by(
                    row_id=row.id).order_by(Column.column_number).all():
                new_section_id = None
                if col.section_id:
                    old_sec = db.session.get(PageSection, col.section_id)
                    if old_sec:
                        # Use `is not None` so an empty dict {} is preserved
                        # rather than becoming None (bool({}) is False).
                        old_content = old_sec.content
                        new_sec = PageSection(
                            section_type=old_sec.section_type,
                            order=old_sec.order,
                            content=_json.loads(_json.dumps(old_content))
                            if old_content is not None else None,
                            page_content_id=new_page.id,
                            custom_code=old_sec.custom_code,
                            label=old_sec.label,
                        )
                        db.session.add(new_sec)
                        db.session.flush()
                        new_section_id = new_sec.id

                        # Rewrite any hardcoded #section-{old_id} references
                        # in the code and custom_code to use the new section ID.
                        # Users often write CSS/JS that targets their section by
                        # its literal ID; after copying the element gets a new
                        # ID so the old references would match nothing.
                        old_ref = f'#section-{old_sec.id}'
                        new_ref = f'#section-{new_sec.id}'

                        if new_sec.content and old_ref in _json.dumps(new_sec.content):
                            from sqlalchemy.orm.attributes import flag_modified as _fm
                            new_sec.content = _json.loads(
                                _json.dumps(new_sec.content).replace(old_ref, new_ref)
                            )
                            _fm(new_sec, 'content')

                        if new_sec.custom_code and old_ref in new_sec.custom_code:
                            new_sec.custom_code = new_sec.custom_code.replace(
                                old_ref, new_ref)

                        # Copy asset links (images / audio / video) so media
                        # sections work after the copy.
                        copy_section_links_and_events(old_sec, new_sec)

                db.session.add(Column(
                    row_id=new_row.id,
                    column_number=col.column_number,
                    section_id=new_section_id,
                    width=col.width,
                ))

    db.session.flush()


@app.route('/admin/websites/<int:website_id>/create-draft', methods=['POST'])
@login_required
@require_perm('website.draft.create')
def create_draft_website(website_id):
    """Clone the live website into a new draft for safe editing."""
    live = Website.query.filter_by(id=website_id, user_id=current_user.root_user_id, is_draft=False).first_or_404()

    # Only one draft at a time
    existing_draft = Website.query.filter_by(user_id=current_user.root_user_id, is_draft=True).first()
    if existing_draft:
        return jsonify(
            {'success': False, 'error': 'A draft already exists. Promote or delete it before creating a new one.'}), 400

    draft = Website(
        user_id=current_user.root_user_id,
        is_draft=True,
        name=live.name,
    )
    _copy_website_settings(live, draft)
    draft.name = live.name  # keep same name; dashboard shows the DRAFT badge
    db.session.add(draft)
    db.session.flush()

    _copy_website_content(live, draft)
    db.session.commit()
    return jsonify({'success': True, 'draft_id': draft.id})


@app.route('/admin/websites/<int:draft_id>/promote-draft', methods=['POST'])
@login_required
@require_perm('website.draft.promote')
def promote_draft_website(draft_id):
    """Replace the live website's settings and pages with the draft's, then
    delete the draft."""
    draft = Website.query.filter_by(
        id=draft_id, user_id=current_user.root_user_id, is_draft=True).first_or_404()
    live = Website.query.filter_by(
        user_id=current_user.root_user_id, is_draft=False).first_or_404()

    try:
        import traceback as _tb

        # 1. Copy settings
        _copy_website_settings(draft, live)
        live.is_draft = False

        # 2. Clear all existing live content (FK-safe deep delete)
        _delete_website_pages(live)
        db.session.flush()

        # 3. Copy draft content → live
        _copy_website_content(draft, live)

        # 4. Delete the draft (all records + website row via bulk deletes)
        _delete_website_all(draft)

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error('promote_draft_website error:\n' + _tb.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/websites/<int:draft_id>/delete-draft', methods=['POST'])
@login_required
@require_perm('website.draft.create')
def delete_draft_website(draft_id):
    """Discard a draft website without affecting the live site."""
    draft = Website.query.filter_by(
        id=draft_id, user_id=current_user.root_user_id, is_draft=True).first_or_404()
    try:
        import traceback as _tb
        _delete_website_all(draft)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error('delete_draft_website error:\n' + _tb.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500


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
@require_perm('sections.edit')
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


@app.route('/move_or_swap_section/<int:section_id>', methods=['PUT'])
@login_required
def move_or_swap_section(section_id):
    try:
        data = request.get_json() or {}

        source_column_id = data.get('sourceColumnId')
        target_column_id = data.get('targetColumnId')

        section = PageSection.query.get_or_404(section_id)
        source_column = Column.query.get(source_column_id)
        target_column = Column.query.get(target_column_id)

        if not source_column or not target_column:
            return jsonify({
                'success': False,
                'error': 'Source or target column not found.'
            }), 404

        if source_column.id == target_column.id:
            return jsonify({
                'success': True,
                'message': 'Section already in this column.'
            })

        # Security check: make sure this section belongs to the logged-in user's website.
        page = PublicPageContent.query.get_or_404(section.page_content_id)
        website = Website.query.get_or_404(page.website_id)

        if not is_owner(website):
            return jsonify({
                'success': False,
                'error': 'Unauthorized.'
            }), 403

        # Make sure both columns belong to the same page.
        if source_column.row.page_content_id != page.id or target_column.row.page_content_id != page.id:
            return jsonify({
                'success': False,
                'error': 'Columns do not belong to the same page.'
            }), 400

        if source_column.section_id != section.id:
            # Recover from stale frontend data by finding the true source column.
            true_source_column = Column.query.filter_by(section_id=section.id).first()

            if not true_source_column:
                return jsonify({
                    'success': False,
                    'error': 'Section is not assigned to a column.'
                }), 400

            source_column = true_source_column

        target_section_id = target_column.section_id

        # Move into empty column OR swap with occupied column.
        target_column.section_id = section.id
        source_column.section_id = target_section_id

        # Keep section.order roughly aligned with visual cell position.
        section.order = target_column.column_number or section.order

        if target_section_id:
            swapped_section = PageSection.query.get(target_section_id)
            if swapped_section:
                swapped_section.order = source_column.column_number or swapped_section.order

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Section moved successfully.'
        })

    except Exception as e:
        db.session.rollback()
        print(f'Error moving/swapping section: {e}')

        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


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
    if not is_owner(website):
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
@require_perm('sections.create')
def add_section(page_id):
    # Query the PublicPageContent to ensure it exists and to get the website
    content = PublicPageContent.query.get_or_404(page_id)
    website = content.website

    # Check if the current user is authorized to modify this page
    if not is_owner(website):
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
            row_number=current_row_number,
            section_group_id=current_row.section_group_id
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


@app.route('/add_row_below/<int:row_id>', methods=['POST'])
@login_required
def add_row_below(row_id):
    try:
        current_row = Row.query.get_or_404(row_id)
        insert_at = current_row.row_number + 1

        rows_to_increment = Row.query.filter(
            Row.page_content_id == current_row.page_content_id,
            Row.row_number >= insert_at
        ).order_by(Row.row_number.asc()).all()

        for row in rows_to_increment:
            row.row_number += 1

        new_row = Row(
            page_content_id=current_row.page_content_id,
            row_number=insert_at,
            section_group_id=current_row.section_group_id
        )
        db.session.add(new_row)
        db.session.flush()

        new_column = Column(row_id=new_row.id, column_number=1, width=100)
        db.session.add(new_column)
        db.session.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/page/<int:page_id>/remove_section/<int:section_id>', methods=['DELETE'])
@login_required
@require_perm('sections.delete')
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
@require_perm('sections.edit')
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


@app.route('/admin/library/upload', methods=['POST'])
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

    # Read raw bytes first so we can preserve the original file unchanged
    file_storage.stream.seek(0)
    raw_bytes = file_storage.stream.read()
    file_storage.stream.seek(0)

    # Detect format from magic bytes — reliable regardless of PIL stream quirks
    if raw_bytes[:3] == b'\xff\xd8\xff':
        orig_ext = 'jpg'
    elif raw_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        orig_ext = 'png'
    elif raw_bytes[:4] == b'RIFF' and raw_bytes[8:12] == b'WEBP':
        orig_ext = 'webp'
    elif raw_bytes[:6] in (b'GIF87a', b'GIF89a'):
        orig_ext = 'gif'
    else:
        orig_ext = None  # unknown — skip saving original
    app.logger.info(
        f'save_optimized_versions: magic-byte format={orig_ext!r}, will {"skip" if orig_ext in (None, "webp") else f"save original as .{orig_ext}"}')

    with Image.open(file_storage.stream) as img:
        img = ImageOps.exif_transpose(img)

        img = ensure_rgb(img)

        # Public WebP
        public_img = img.copy()
        if public_img.width > PUBLIC_MAX_WIDTH:
            ratio = PUBLIC_MAX_WIDTH / public_img.width
            new_height = int(public_img.height * ratio)
            public_img = public_img.resize((PUBLIC_MAX_WIDTH, new_height), Image.LANCZOS)

        public_filename = f"{base_name}.webp"
        public_path = os.path.join(output_dir, public_filename)
        public_img.save(public_path, "WEBP", quality=PUBLIC_QUALITY, method=6)

        # Thumbnail WebP
        thumb_img = img.copy()
        thumb_img.thumbnail(THUMB_SIZE, Image.LANCZOS)

        thumb_filename = f"{base_name}_thumb.webp"
        thumb_path = os.path.join(output_dir, thumb_filename)
        thumb_img.save(thumb_path, "WEBP", quality=THUMB_QUALITY, method=6)

    # Save original bytes verbatim — skip if already WebP or format unknown
    if orig_ext and orig_ext != 'webp':
        orig_filename = f"{base_name}_original.{orig_ext}"
        with open(os.path.join(output_dir, orig_filename), 'wb') as f:
            f.write(raw_bytes)
    else:
        orig_filename = None

    return {
        "public_filename": public_filename,
        "thumb_filename": thumb_filename,
        "original_filename": orig_filename,  # None when source was already WebP
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


@app.route('/admin/dashboard/library')
@login_required
def old_photo_library_redirect():
    return redirect(url_for('asset_library'))


def migrate_pictures_to_assets():
    pictures = Picture.query.all()

    for pic in pictures:
        existing = Asset.query.filter_by(
            user_id=pic.user_id,
            url=pic.url
        ).first()

        if existing:
            continue

        filename = os.path.basename(pic.url or 'image.webp')
        extension = get_asset_extension(filename) or 'webp'

        asset = Asset(
            user_id=pic.user_id,
            folder_id=None,
            original_filename=filename,
            stored_filename=filename,
            url=pic.url,
            thumbnail_url=pic.thumbnail_url,
            asset_type='image',
            mime_type='image/webp' if extension == 'webp' else f'image/{extension}',
            extension=extension,
            file_size=0
        )

        db.session.add(asset)

    db.session.commit()


@app.route('/admin/dashboard/library', endpoint='photo_library')
@login_required
def photo_library():
    folders = Folder.query.filter_by(user_id=current_user.id).all()
    root_pictures = Picture.query.filter_by(
        user_id=current_user.id,
        folder_id=None
    ).order_by(Picture.upload_date.desc()).all()

    return render_template(
        'photo_library.html',
        folders=folders,
        root_pictures=root_pictures,
        current_folder=None
    )


def update_images_section(section, form_data):
    max_width_raw = (form_data.get('image_max_width') or '').strip()
    section.content = {
        'image_layout': form_data.get('image_layout', 'single'),
        'image_fit': form_data.get('image_fit', 'natural'),
        'image_radius': form_data.get('image_radius', '10'),
        'image_max_width': max_width_raw if max_width_raw.isdigit() else '',
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


#
# @app.route('/delete_section_image/<int:link_id>', methods=['DELETE'])
# @login_required
# def delete_section_image(link_id):
#     try:
#         section_image = SectionImage.query.get_or_404(link_id)
#
#         section = PageSection.query.get_or_404(section_image.section_id)
#         page = PublicPageContent.query.get_or_404(section.page_content_id)
#         website = Website.query.get_or_404(page.website_id)
#
#         if not is_owner(website):
#             return jsonify({
#                 'success': False,
#                 'error': 'Unauthorized.'
#             }), 403
#
#         db.session.delete(section_image)
#         db.session.commit()
#
#         return jsonify({
#             'success': True,
#             'message': 'Image removed from section.'
#         })
#
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 500

@app.route('/get_uploaded_images', methods=['GET'])
@login_required
def get_uploaded_images():
    section_id = request.args.get('section_id', type=int)

    if not section_id:
        return jsonify({'images': []})

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'images': []}), 403

    results = (
        db.session.query(Asset, SectionAsset)
        .join(SectionAsset, Asset.id == SectionAsset.asset_id)
        .filter(
            SectionAsset.section_id == section.id,
            Asset.asset_type == 'image'
        )
        .order_by(SectionAsset.order)
        .all()
    )

    images_data = [
        {
            'id': asset.id,
            'asset_id': asset.id,
            'link_id': link.id,
            'url': asset.url,
            'thumbnail_url': asset.thumbnail_url or asset.url,
            'order': link.order,
            'filename': asset.original_filename
        }
        for asset, link in results
    ]

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


@app.route('/add_assets_to_section', methods=['POST'])
@login_required
def add_assets_to_section():
    data = request.get_json() or {}

    section_id = data.get('section_id')
    asset_ids = (
            data.get('asset_ids')
            or data.get('image_ids')
            or data.get('audio_ids')
            or data.get('video_ids')
            or []
    )

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    section_asset_rules = {
        'image': 'image',
        'image_gallery': 'image',
        'images': 'image',
        'music': 'audio',
        'video': 'video',
        'videos': 'video',
    }

    required_asset_type = section_asset_rules.get(section.section_type)

    if not required_asset_type:
        return jsonify({
            'status': 'error',
            'message': f'This section does not accept library assets: {section.section_type}'
        }), 400

    usage_type = data.get('usage_type') or {
        'image': 'section-image',
        'image_gallery': 'section-image',
        'images': 'section-image',
        'music': 'section-music',
        'video': 'section-video',
        'videos': 'section-video',
    }.get(section.section_type, 'section-asset')

    max_order = db.session.query(func.coalesce(func.max(SectionAsset.order), 0)).filter_by(
        section_id=section.id
    ).scalar() or 0

    added = 0

    for asset_id in asset_ids:
        asset = Asset.query.filter_by(
            id=asset_id,
            user_id=current_user.id,
            asset_type=required_asset_type
        ).first()

        if not asset:
            continue

        existing = SectionAsset.query.filter_by(
            section_id=section.id,
            asset_id=asset.id,
            usage_type=usage_type
        ).first()

        if existing:
            continue

        max_order += 1

        db.session.add(SectionAsset(
            section_id=section.id,
            asset_id=asset.id,
            usage_type=usage_type,
            order=max_order
        ))

        added += 1

    db.session.commit()

    return jsonify({
        'status': 'success',
        'success': True,
        'added': added
    })


def get_or_create_asset_visitor_id():
    visitor_id = request.cookies.get('uwebia_asset_visitor_id')

    if visitor_id:
        return visitor_id, False

    visitor_id = secrets.token_urlsafe(32)
    return visitor_id, True


def hash_asset_visitor_id(visitor_id):
    return hashlib.sha256(visitor_id.encode('utf-8')).hexdigest()


@app.route('/get_section_videos', methods=['GET'])
@login_required
def get_section_videos():
    section_id = request.args.get('section_id', type=int)

    if not section_id:
        return jsonify({'videos': []})

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'videos': []}), 403

    results = (
        db.session.query(Asset, SectionAsset)
        .join(SectionAsset, Asset.id == SectionAsset.asset_id)
        .filter(
            SectionAsset.section_id == section.id,
            Asset.asset_type == 'video'
        )
        .order_by(SectionAsset.order)
        .all()
    )

    videos_data = [
        {
            'id': asset.id,
            'asset_id': asset.id,
            'link_id': link.id,
            'url': asset.url,
            'thumbnail_url': asset.thumbnail_url or '',
            'mime_type': asset.mime_type or 'video/mp4',
            'order': link.order,
            'filename': asset.original_filename,
            'extension': asset.extension,
            'file_size_label': format_bytes(asset.file_size),
            'play_count': asset.play_count or 0,
            'unique_play_count': asset.unique_play_count or 0,
            'last_played_at': asset.last_played_at.isoformat() if asset.last_played_at else None
        }
        for asset, link in results
    ]

    return jsonify({'videos': videos_data})


@app.route('/remove_video_from_section', methods=['POST'])
@login_required
def remove_video_from_section():
    data = request.get_json() or {}

    section_id = data.get('sectionId') or data.get('section_id')
    link_ids = data.get('linkIds') or data.get('link_ids') or []

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    if not link_ids:
        return jsonify({'status': 'error', 'message': 'No videos selected.'}), 400

    SectionAsset.query.filter(
        SectionAsset.id.in_(link_ids),
        SectionAsset.section_id == section.id
    ).delete(synchronize_session=False)

    db.session.commit()

    return jsonify({
        'status': 'success',
        'success': True,
        'message': 'Video removed from section.'
    })


@app.route('/reorder_section_videos', methods=['POST'])
@login_required
def reorder_section_videos():
    data = request.get_json() or {}

    section_id = data.get('section_id')
    ordered_link_ids = data.get('ordered_link_ids') or []

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    for index, link_id in enumerate(ordered_link_ids, start=1):
        link = SectionAsset.query.filter_by(
            id=link_id,
            section_id=section.id
        ).first()

        if link:
            link.order = index

    db.session.commit()

    return jsonify({'status': 'success', 'success': True})


@app.route('/get_section_music', methods=['GET'])
@login_required
def get_section_music():
    section_id = request.args.get('section_id', type=int)

    if not section_id:
        return jsonify({'tracks': []})

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'tracks': []}), 403

    results = (
        db.session.query(Asset, SectionAsset)
        .join(SectionAsset, Asset.id == SectionAsset.asset_id)
        .filter(
            SectionAsset.section_id == section.id,
            Asset.asset_type == 'audio'
        )
        .order_by(SectionAsset.order)
        .all()
    )

    tracks_data = [
        {
            'id': asset.id,
            'asset_id': asset.id,
            'link_id': link.id,
            'url': asset.url,
            'mime_type': asset.mime_type or 'audio/mpeg',
            'order': link.order,
            'filename': asset.original_filename,
            'extension': asset.extension,
            'file_size_label': format_bytes(asset.file_size),
            'play_count': asset.play_count or 0,
            'unique_play_count': asset.unique_play_count or 0,
            'last_played_at': asset.last_played_at.isoformat() if asset.last_played_at else None
        }
        for asset, link in results
    ]

    return jsonify({'tracks': tracks_data})


@app.route('/remove_music_from_section', methods=['POST'])
@login_required
def remove_music_from_section():
    data = request.get_json() or {}

    section_id = data.get('sectionId') or data.get('section_id')
    link_ids = data.get('linkIds') or data.get('link_ids') or []

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    if not link_ids:
        return jsonify({'status': 'error', 'message': 'No tracks selected.'}), 400

    SectionAsset.query.filter(
        SectionAsset.id.in_(link_ids),
        SectionAsset.section_id == section.id
    ).delete(synchronize_session=False)

    db.session.commit()

    return jsonify({
        'status': 'success',
        'success': True,
        'message': 'Music removed from section.'
    })


@app.route('/reorder_section_music', methods=['POST'])
@login_required
def reorder_section_music():
    data = request.get_json() or {}

    section_id = data.get('section_id')
    ordered_link_ids = data.get('ordered_link_ids') or []

    section = PageSection.query.get_or_404(section_id)

    if not user_owns_section(section):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    for index, link_id in enumerate(ordered_link_ids, start=1):
        link = SectionAsset.query.filter_by(
            id=link_id,
            section_id=section.id
        ).first()

        if link:
            link.order = index

    db.session.commit()

    return jsonify({'status': 'success', 'success': True})


@app.route('/add_images_from_library', methods=['POST'])
@login_required
def add_images_from_library_legacy():
    data = request.get_json() or {}

    return add_assets_to_section()


# Create a new folder
@app.route('/admin/library/create_folder', methods=['POST'])
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
@app.route('/admin/dashboard/library/folder/<int:folder_id>', endpoint='view_folder')
@login_required
def view_folder(folder_id):
    folder = Folder.query.filter_by(
        id=folder_id,
        user_id=current_user.id
    ).first_or_404()

    folders = Folder.query.filter_by(user_id=current_user.id).all()
    pictures = Picture.query.filter_by(
        user_id=current_user.id,
        folder_id=folder_id
    ).order_by(Picture.upload_date.desc()).all()

    return render_template(
        'photo_library.html',
        folders=folders,
        root_pictures=pictures,
        current_folder=folder
    )


# Move image to folder
@app.route('/admin/library/move_image', methods=['POST'])
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
@app.route('/admin/library/delete_image/<int:image_id>', methods=['POST'])
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
@require_perm('pages.edit')
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
@require_perm('pages.edit')
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


def should_track_page_visit(is_preview=False):
    if is_preview:
        return False

    # Do not count your own logged-in admin/editor visits.
    if current_user.is_authenticated:
        return False

    user_agent = (request.headers.get('User-Agent') or '').lower()

    bot_keywords = [
        'bot',
        'crawler',
        'spider',
        'preview',
        'facebookexternalhit',
        'slackbot',
        'discordbot',
        'whatsapp',
        'telegrambot'
    ]

    if any(keyword in user_agent for keyword in bot_keywords):
        return False

    return True


def get_analytics_settings_for_user(user_id):
    settings = AnalyticsSettings.query.filter_by(user_id=user_id).first()

    if not settings:
        settings = AnalyticsSettings(
            user_id=user_id,
            geoip_enabled=False
        )
        db.session.add(settings)
        db.session.commit()

    return settings


def is_public_ip_address(ip_address):
    if not ip_address:
        return False

    try:
        ip = ipaddress.ip_address(ip_address)
        return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_link_local
        )
    except ValueError:
        return False


def lookup_ip_location_for_website(website, ip_address):
    """
    Optional local GeoIP lookup.
    No third-party API call is made.

    Supports using multiple local databases at once:
    - City: country, region, city, lat/lon
    - Country: country only
    - ASN: network/provider
    """
    if not website or not ip_address:
        return {}

    if not is_public_ip_address(ip_address):
        return {}

    settings = AnalyticsSettings.query.filter_by(user_id=website.user_id).first()

    if not settings or not settings.geoip_enabled:
        return {}

    try:
        import geoip2.database

        result = {
            'location_source': 'local_geoip'
        }

        # 1. City database, best location option
        if settings.geoip_city_database_path and os.path.exists(settings.geoip_city_database_path):
            try:
                with geoip2.database.Reader(settings.geoip_city_database_path) as reader:
                    response = reader.city(ip_address)

                    result.update({
                        'geoip_database_type': settings.geoip_city_database_type,
                        'country': response.country.name,
                        'country_iso': response.country.iso_code,
                        'region': response.subdivisions.most_specific.name,
                        'city': response.city.name,
                        'latitude': response.location.latitude,
                        'longitude': response.location.longitude
                    })
            except Exception as e:
                print(f"GeoIP City lookup failed for {ip_address}: {e}")

        # 2. Country fallback if City was not available or did not return country
        if not result.get('country') and settings.geoip_country_database_path and os.path.exists(
                settings.geoip_country_database_path):
            try:
                with geoip2.database.Reader(settings.geoip_country_database_path) as reader:
                    response = reader.country(ip_address)

                    result.update({
                        'geoip_database_type': result.get(
                            'geoip_database_type') or settings.geoip_country_database_type,
                        'country': response.country.name,
                        'country_iso': response.country.iso_code
                    })
            except Exception as e:
                print(f"GeoIP Country lookup failed for {ip_address}: {e}")

        # 3. ASN can be added alongside City/Country
        if settings.geoip_asn_database_path and os.path.exists(settings.geoip_asn_database_path):
            try:
                with geoip2.database.Reader(settings.geoip_asn_database_path) as reader:
                    response = reader.asn(ip_address)

                    result.update({
                        'asn_number': response.autonomous_system_number,
                        'asn_organization': response.autonomous_system_organization
                    })

                    if result.get('geoip_database_type'):
                        result[
                            'geoip_database_type'] = f"{result['geoip_database_type']} + {settings.geoip_asn_database_type}"
                    else:
                        result['geoip_database_type'] = settings.geoip_asn_database_type

            except Exception as e:
                print(f"GeoIP ASN lookup failed for {ip_address}: {e}")

        return result

    except Exception as e:
        print(f"GeoIP lookup failed for {ip_address}: {e}")
        return {}


def cleanup_unused_geoip_files(user_id):
    """
    Delete unused .mmdb files for this user from database/analytics.

    Keeps only files currently referenced by AnalyticsSettings.
    Removes old temp files, old single-database files, and leftovers from previous versions.
    """
    analytics_folder = os.path.join(database_folder, 'analytics')

    if not os.path.exists(analytics_folder):
        return 0

    settings = AnalyticsSettings.query.filter_by(user_id=user_id).first()

    active_paths = set()

    if settings:
        possible_paths = [
            getattr(settings, 'geoip_city_database_path', None),
            getattr(settings, 'geoip_country_database_path', None),
            getattr(settings, 'geoip_asn_database_path', None),
        ]

        for path in possible_paths:
            if path:
                active_paths.add(os.path.abspath(path))

    deleted_count = 0

    for filename in os.listdir(analytics_folder):
        if not filename.lower().endswith('.mmdb'):
            continue

        # Only clean files for this user.
        # Prevent accidentally deleting another user's files in the future.
        if not filename.startswith(f'user_{user_id}_geoip_'):
            continue

        file_path = os.path.abspath(os.path.join(analytics_folder, filename))

        if file_path not in active_paths:
            try:
                os.remove(file_path)
                deleted_count += 1
                print(f"Deleted unused GeoIP database: {file_path}")
            except Exception as e:
                print(f"Failed to delete unused GeoIP database {file_path}: {e}")

    return deleted_count


@app.route('/admin/dashboard/analytics/geoip/upload', methods=['POST'])
@login_required
@require_perm('analytics.geoip')
def upload_geoip_database():
    settings = get_analytics_settings_for_user(current_user.id)

    geoip_file = request.files.get('geoip_database')

    if not geoip_file or not geoip_file.filename:
        return jsonify({
            'success': False,
            'message': 'Please choose a GeoIP .mmdb database file.'
        }), 400

    filename = secure_filename(geoip_file.filename)

    if not filename.lower().endswith('.mmdb'):
        return jsonify({
            'success': False,
            'message': 'Only .mmdb GeoIP database files are allowed.'
        }), 400

    analytics_folder = os.path.join(database_folder, 'analytics')
    os.makedirs(analytics_folder, exist_ok=True)

    temp_path = os.path.join(
        analytics_folder,
        f'user_{current_user.id}_geoip_upload_temp.mmdb'
    )

    geoip_file.save(temp_path)

    try:
        import geoip2.database

        with geoip2.database.Reader(temp_path) as reader:
            database_type = reader.metadata().database_type

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)

        return jsonify({
            'success': False,
            'message': f'Could not read this GeoIP database: {str(e)}'
        }), 400

    city_types = ['GeoLite2-City', 'GeoIP2-City']
    country_types = ['GeoLite2-Country', 'GeoIP2-Country']
    asn_types = ['GeoLite2-ASN', 'GeoIP2-ASN']

    if database_type in city_types:
        final_path = os.path.join(
            analytics_folder,
            f'user_{current_user.id}_geoip_city.mmdb'
        )

        if os.path.exists(final_path):
            os.remove(final_path)

        os.replace(temp_path, final_path)

        settings.geoip_city_database_path = final_path
        settings.geoip_city_database_name = filename
        settings.geoip_city_database_type = database_type

        message = f'{database_type} uploaded. City-level location lookup is enabled.'

    elif database_type in country_types:
        final_path = os.path.join(
            analytics_folder,
            f'user_{current_user.id}_geoip_country.mmdb'
        )

        if os.path.exists(final_path):
            os.remove(final_path)

        os.replace(temp_path, final_path)

        settings.geoip_country_database_path = final_path
        settings.geoip_country_database_name = filename
        settings.geoip_country_database_type = database_type

        message = f'{database_type} uploaded. Country-level lookup is enabled.'

    elif database_type in asn_types:
        final_path = os.path.join(
            analytics_folder,
            f'user_{current_user.id}_geoip_asn.mmdb'
        )

        if os.path.exists(final_path):
            os.remove(final_path)

        os.replace(temp_path, final_path)

        settings.geoip_asn_database_path = final_path
        settings.geoip_asn_database_name = filename
        settings.geoip_asn_database_type = database_type

        message = f'{database_type} uploaded. Network/provider lookup is enabled.'

    else:
        if os.path.exists(temp_path):
            os.remove(temp_path)

        return jsonify({
            'success': False,
            'message': f'This database type is "{database_type}". Supported types are City, Country, and ASN .mmdb databases.'
        }), 400

    settings.geoip_enabled = True
    settings.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.session.commit()
    cleanup_unused_geoip_files(current_user.id)

    return jsonify({
        'success': True,
        'message': message,
        'geoip_database_type': database_type,
        'geoip_city_database_name': settings.geoip_city_database_name,
        'geoip_country_database_name': settings.geoip_country_database_name,
        'geoip_asn_database_name': settings.geoip_asn_database_name
    })


@app.route('/admin/dashboard/analytics/geoip/disable', methods=['POST'])
@login_required
@require_perm('analytics.geoip')
def disable_geoip_database():
    settings = get_analytics_settings_for_user(current_user.id)

    settings.geoip_enabled = False
    settings.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Approximate location and network analytics disabled.'
    })


@app.route('/admin/dashboard/analytics/geoip/delete', methods=['POST'])
@login_required
@require_perm('analytics.geoip')
def delete_geoip_database():
    settings = get_analytics_settings_for_user(current_user.id)

    paths_to_delete = [
        settings.geoip_city_database_path,
        settings.geoip_country_database_path,
        settings.geoip_asn_database_path
    ]

    for path in paths_to_delete:
        if path and os.path.exists(path):
            os.remove(path)

    settings.geoip_enabled = False

    settings.geoip_city_database_path = None
    settings.geoip_city_database_name = None
    settings.geoip_city_database_type = None

    settings.geoip_country_database_path = None
    settings.geoip_country_database_name = None
    settings.geoip_country_database_type = None

    settings.geoip_asn_database_path = None
    settings.geoip_asn_database_name = None
    settings.geoip_asn_database_type = None

    settings.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'All local GeoIP databases deleted.'
    })


GEOIP_DB_PATH = os.path.join(database_folder, 'GeoLite2-City.mmdb')


def lookup_ip_location(ip_address):
    if not ip_address:
        return {}

    if ip_address.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                              '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                              '172.28.', '172.29.', '172.30.', '172.31.')):
        return {}

    if not os.path.exists(GEOIP_DB_PATH):
        return {}

    try:
        import geoip2.database

        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)

            return {
                'country': response.country.name,
                'region': response.subdivisions.most_specific.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'source': 'geoip_local'
            }

    except Exception:
        return {}


def track_page_visit(website, page, visitor_id):
    import threading

    # Capture request values now — they won't be accessible from a background thread
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

    path = request.path
    referrer = request.referrer
    ua = request.headers.get('User-Agent')
    website_id = website.id
    page_id = page.id

    def _do_track():
        with app.app_context():
            try:
                # Look up the website again inside the new context
                _website = Website.query.get(website_id)
                location = lookup_ip_location_for_website(_website, ip_address) if _website else {}
                visit = PageVisit(
                    website_id=website_id,
                    page_id=page_id,
                    visitor_id=visitor_id,
                    path=path,
                    referrer=referrer,
                    user_agent=ua,
                    ip_address=ip_address,
                    country=location.get('country'),
                    country_iso=location.get('country_iso'),
                    region=location.get('region'),
                    city=location.get('city'),
                    latitude=location.get('latitude'),
                    longitude=location.get('longitude'),
                    location_source=location.get('location_source'),
                    asn_number=location.get('asn_number'),
                    asn_organization=location.get('asn_organization'),
                    geoip_database_type=location.get('geoip_database_type')
                )
                db.session.add(visit)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'track_page_visit background error: {e}')

    t = threading.Thread(target=_do_track, daemon=True)
    t.start()


@app.route('/admin/dashboard/settings', methods=['GET', 'POST'])
@login_required
@require_perm('settings.view')
def settings_page():
    timezone_choices = pytz.common_timezones

    if request.method == 'POST':
        admin_url_key_enabled = request.form.get('admin_url_key_enabled') == 'on'
        admin_url_key = normalize_admin_url_key(request.form.get('admin_url_key'))

        if admin_url_key_enabled and not admin_url_key:
            flash('Please enter an admin URL key or turn off the custom admin login URL setting.', 'error')
            return redirect(url_for('settings_page'))

        current_user.admin_url_key_enabled = admin_url_key_enabled
        current_user.admin_url_key = admin_url_key if admin_url_key_enabled else None

        timezone_name = request.form.get('timezone', 'America/Chicago').strip()
        date_format = request.form.get('date_format', '%b %d, %Y %I:%M %p').strip()

        if timezone_name not in pytz.all_timezones:
            flash('Invalid timezone selected.', 'error')
            return redirect(url_for('settings_page'))

        allowed_date_formats = [
            '%b %d, %Y %I:%M %p',
            '%m/%d/%Y %I:%M %p',
            '%Y-%m-%d %H:%M',
            '%d %b %Y %H:%M'
        ]

        if date_format not in allowed_date_formats:
            date_format = '%b %d, %Y %I:%M %p'

        current_user.timezone = timezone_name
        current_user.date_format = date_format

        account_username = request.form.get('account_username', '').strip().lower()
        account_email = request.form.get('account_email', '').strip().lower()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_new_password = request.form.get('confirm_new_password', '')

        if not account_username:
            flash('Username cannot be blank.', 'error')
            return redirect(url_for('settings_page'))

        if not account_email:
            flash('Email cannot be blank.', 'error')
            return redirect(url_for('settings_page'))

        existing_username = User.query.filter(
            User.username == account_username,
            User.id != current_user.id
        ).first()

        if existing_username:
            flash('That username is already in use.', 'error')
            return redirect(url_for('settings_page'))

        existing_email = User.query.filter(
            User.email == account_email,
            User.id != current_user.id
        ).first()

        if existing_email:
            flash('That email is already in use.', 'error')
            return redirect(url_for('settings_page'))

        password_change_requested = bool(new_password or confirm_new_password)

        if password_change_requested:
            if not current_password:
                flash('Enter your current password to change your password.', 'error')
                return redirect(url_for('settings_page'))

            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('settings_page'))

            if new_password != confirm_new_password:
                flash('New passwords do not match.', 'error')
                return redirect(url_for('settings_page'))

            current_user.set_password(new_password)

        current_user.username = account_username
        current_user.email = account_email

        db.session.commit()

        if current_user.admin_url_key_enabled and current_user.admin_url_key:
            flash(
                f'Settings saved. Your custom admin login URL is /admin/login/{current_user.admin_url_key}',
                'success'
            )
        else:
            flash('Settings saved. Custom admin login URL is disabled.', 'success')
        return redirect(url_for('settings_page'))

    return render_template(
        'settings.html',
        timezone_choices=timezone_choices,
        selected_timezone=current_user.timezone or 'America/Chicago',
        selected_date_format=current_user.date_format or '%b %d, %Y %I:%M %p',
        admin_url_key_enabled=current_user.admin_url_key_enabled,
        admin_url_key=current_user.admin_url_key or '',
        two_factor_enabled=current_user.two_factor_enabled,
        two_factor_email=current_user.two_factor_email or current_user.email,
        email_settings=get_email_settings(),
        account_username=current_user.username,
        account_email=current_user.email,
    )


# ── Backup / Restore ──────────────────────────────────────────────────────────

BACKUP_VERSION = 1


def _serialize_backup(uid):
    """Collect all data for the given admin user and return a JSON-serialisable dict."""
    websites = Website.query.filter_by(user_id=uid).all()
    website_ids = [w.id for w in websites]

    page_folders = PageFolder.query.filter(PageFolder.website_id.in_(website_ids)).all() if website_ids else []
    pages = PublicPageContent.query.filter(PublicPageContent.website_id.in_(website_ids)).all() if website_ids else []
    page_ids = [p.id for p in pages]

    section_groups = SectionGroup.query.filter(SectionGroup.page_content_id.in_(page_ids)).all() if page_ids else []
    rows = Row.query.filter(Row.page_content_id.in_(page_ids)).all() if page_ids else []
    row_ids = [r.id for r in rows]

    columns = Column.query.filter(Column.row_id.in_(row_ids)).all() if row_ids else []
    sections = PageSection.query.filter(PageSection.page_content_id.in_(page_ids)).all() if page_ids else []
    section_ids = [s.id for s in sections]

    section_assets = SectionAsset.query.filter(SectionAsset.section_id.in_(section_ids)).all() if section_ids else []
    section_images = SectionImage.query.filter(SectionImage.section_id.in_(section_ids)).all() if section_ids else []
    picture_ids = list({si.picture_id for si in section_images})
    pictures = Picture.query.filter(Picture.id.in_(picture_ids)).all() if picture_ids else []
    pic_folder_ids = list({p.folder_id for p in pictures if p.folder_id})
    pic_folders = Folder.query.filter(Folder.id.in_(pic_folder_ids)).all() if pic_folder_ids else []

    calendars = Calendar.query.filter(Calendar.website_id.in_(website_ids)).all() if website_ids else []
    cal_ids = [c.id for c in calendars]
    cal_events = CalendarEvent.query.filter(
        CalendarEvent.calendar_id.in_(cal_ids), CalendarEvent.source == 'local'
    ).all() if cal_ids else []
    cal_subs = CalendarSubscription.query.filter(CalendarSubscription.calendar_id.in_(cal_ids)).all() if cal_ids else []

    ai_agents = AIAgent.query.filter(AIAgent.website_id.in_(website_ids)).all() if website_ids else []

    sg_templates = SectionGroupTemplate.query.filter(
        SectionGroupTemplate.website_id.in_(website_ids)).all() if website_ids else []
    sec_templates = SectionTemplate.query.filter(
        SectionTemplate.website_id.in_(website_ids)).all() if website_ids else []
    page_templates = PageTemplate.query.filter(PageTemplate.website_id.in_(website_ids)).all() if website_ids else []

    asset_folders = AssetFolder.query.filter_by(user_id=uid).all()
    assets = Asset.query.filter_by(user_id=uid).all()

    perm_groups = PermissionGroup.query.filter_by(owner_user_id=uid).all()
    sub_admins = User.query.filter_by(parent_user_id=uid).all()

    return {
        'meta': {
            'version': BACKUP_VERSION,
            'created_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            'owner_username': current_user.username,
            'owner_user_id': uid,
        },
        'websites': [{'id': w.id, 'name': w.name, 'description': w.description,
                      'is_draft': w.is_draft,
                      'background_color': w.background_color, 'text_color': w.text_color,
                      'background_image_url': w.background_image_url,
                      'background_image_repeat': w.background_image_repeat,
                      'background_image_repeat_x': w.background_image_repeat_x,
                      'background_image_mobile_cover': w.background_image_mobile_cover,
                      'background_image_zoom': w.background_image_zoom,
                      'public_navbar_items': w.public_navbar_items,
                      'public_navbar_style': w.public_navbar_style,
                      'forum_enabled': w.forum_enabled,
                      'forum_show_in_navbar': w.forum_show_in_navbar,
                      'forum_require_login_to_view': w.forum_require_login_to_view,
                      'forum_require_login_to_post': w.forum_require_login_to_post,
                      'forum_title': w.forum_title,
                      'forum_description': w.forum_description,
                      'forum_account_verification_enabled': w.forum_account_verification_enabled,
                      'forum_allow_unverified_login': w.forum_allow_unverified_login,
                      } for w in websites],
        'page_folders': [{'id': f.id, 'website_id': f.website_id, 'name': f.name,
                          'sort_order': f.sort_order} for f in page_folders],
        'pages': [{'id': p.id, 'website_id': p.website_id,
                   'page_folder_id': p.page_folder_id, 'folder_sort_order': p.folder_sort_order,
                   'name': p.name, 'description': p.description,
                   'sort_order': p.sort_order, 'slug': p.slug,
                   'site_active_status': p.site_active_status,
                   'background_color': p.background_color, 'text_color': p.text_color,
                   'custom_code': p.custom_code,
                   'last_edited_at': p.last_edited_at.isoformat() if p.last_edited_at else None,
                   } for p in pages],
        'section_groups': [{'id': g.id, 'page_content_id': g.page_content_id,
                            'name': g.name, 'anchor_slug': g.anchor_slug, 'group_order': g.group_order,
                            'background_color': g.background_color,
                            'background_opacity': g.background_opacity, 'padding': g.padding,
                            'border_radius': g.border_radius, 'max_width': g.max_width,
                            'background_image_url': g.background_image_url,
                            'background_image_size': g.background_image_size,
                            'background_image_position': g.background_image_position,
                            'background_overlay_color': g.background_overlay_color,
                            'background_overlay_opacity': g.background_overlay_opacity,
                            } for g in section_groups],
        'rows': [{'id': r.id, 'page_content_id': r.page_content_id,
                  'row_number': r.row_number, 'section_group_id': r.section_group_id} for r in rows],
        'columns': [{'id': c.id, 'row_id': c.row_id, 'column_number': c.column_number,
                     'section_id': c.section_id, 'width': c.width} for c in columns],
        'sections': [{'id': s.id, 'section_type': s.section_type, 'order': s.order,
                      'content': s.content, 'page_content_id': s.page_content_id,
                      'custom_code': s.custom_code, 'label': s.label} for s in sections],
        'section_assets': [{'section_id': sa.section_id, 'asset_id': sa.asset_id,
                            'usage_type': sa.usage_type, 'order': sa.order} for sa in section_assets],
        'section_images': [{'section_id': si.section_id, 'picture_id': si.picture_id,
                            'order': si.order} for si in section_images],
        'pictures': [{'id': p.id, 'url': p.url, 'thumbnail_url': p.thumbnail_url,
                      'original_url': p.original_url, 'folder_id': p.folder_id} for p in pictures],
        'picture_folders': [{'id': f.id, 'name': f.name} for f in pic_folders],
        'calendars': [{'id': c.id, 'name': c.name, 'description': c.description,
                       'website_id': c.website_id, 'styles': c.styles} for c in calendars],
        'calendar_events': [{'id': e.id, 'title': e.title, 'description': e.description,
                             'start': e.start.isoformat(), 'end': e.end.isoformat() if e.end else None,
                             'background_color': e.background_color,
                             'calendar_id': e.calendar_id, 'section_id': e.section_id} for e in cal_events],
        'calendar_subscriptions': [{'id': s.id, 'calendar_id': s.calendar_id,
                                    'name': s.name, 'url': s.url} for s in cal_subs],
        'ai_agents': [{'id': a.id, 'website_id': a.website_id, 'name': a.name,
                       'provider': a.provider, 'api_url': a.api_url, 'api_key': a.api_key,
                       'model': a.model, 'system_prompt': a.system_prompt,
                       'capabilities': a.capabilities} for a in ai_agents],
        'asset_folders': [{'id': f.id, 'name': f.name, 'asset_type': f.asset_type} for f in asset_folders],
        'assets': [{'id': a.id, 'folder_id': a.folder_id,
                    'original_filename': a.original_filename,
                    'stored_filename': a.stored_filename,
                    'original_stored_filename': a.original_stored_filename,
                    'url': a.url, 'thumbnail_url': a.thumbnail_url,
                    'asset_type': a.asset_type, 'mime_type': a.mime_type,
                    'extension': a.extension, 'file_size': a.file_size} for a in assets],
        'section_group_templates': [{'id': t.id, 'website_id': t.website_id, 'name': t.name,
                                     'description': t.description, 'template_data': t.template_data,
                                     'row_count': t.row_count, 'section_count': t.section_count} for t in sg_templates],
        'section_templates': [{'id': t.id, 'website_id': t.website_id, 'name': t.name,
                               'section_type': t.section_type, 'content': t.content,
                               'custom_code': t.custom_code} for t in sec_templates],
        'page_templates': [{'id': t.id, 'website_id': t.website_id, 'name': t.name,
                            'description': t.description, 'template_data': t.template_data,
                            'group_count': t.group_count, 'section_count': t.section_count} for t in page_templates],
        'permission_groups': [{'id': g.id, 'name': g.name, 'description': g.description,
                               'permissions': g.permissions} for g in perm_groups],
        'sub_admins': [{'id': u.id, 'username': u.username, 'email': u.email,
                        'password_hash': u.password_hash,
                        'permission_group_id': u.permission_group_id,
                        'permissions': u.permissions, '_is_active': u._is_active} for u in sub_admins],
    }


@app.route('/admin/settings/backup/export')
@login_required
def export_backup():
    if current_user.is_sub_admin:
        return _utf8_json({'error': 'Permission denied'}, 403)

    include_files = request.args.get('include_files', '1') != '0'
    uid = current_user.id
    data = _serialize_backup(uid)
    json_bytes = json.dumps(data, indent=2, default=str).encode('utf-8')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('backup.json', json_bytes)
        if include_files:
            user_assets_dir = os.path.join(uploads_folder, str(uid), 'assets')
            if os.path.isdir(user_assets_dir):
                for fname in os.listdir(user_assets_dir):
                    fpath = os.path.join(user_assets_dir, fname)
                    if os.path.isfile(fpath):
                        zf.write(fpath, f'assets/{fname}')

    buf.seek(0)
    ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    suffix = '' if include_files else '_data_only'
    return send_file(buf, as_attachment=True,
                     download_name=f'uwebia_backup_{ts}{suffix}.zip',
                     mimetype='application/zip')


@app.route('/admin/settings/backup/import', methods=['POST'])
@login_required
def import_backup():
    if current_user.is_sub_admin:
        return _utf8_json({'error': 'Permission denied'}, 403)

    uploaded = request.files.get('backup_file')
    if not uploaded:
        return _utf8_json({'success': False, 'error': 'No file uploaded'}, 400)

    uid = current_user.id
    try:
        raw = uploaded.read()
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            if 'backup.json' not in zf.namelist():
                return _utf8_json({'success': False, 'error': 'Invalid backup: missing backup.json'}, 400)
            data = json.loads(zf.read('backup.json'))

            if data.get('meta', {}).get('version') != BACKUP_VERSION:
                return _utf8_json({'success': False,
                                   'error': f'Unsupported backup version: {data.get("meta", {}).get("version")}'}, 400)

            old_uid = data['meta']['owner_user_id']

            # ── Wipe existing data ────────────────────────────────────────────
            for w in Website.query.filter_by(user_id=uid).all():
                _delete_website_all(w)
            # Delete sub-admins and permission groups
            User.query.filter_by(parent_user_id=uid).delete(synchronize_session=False)
            PermissionGroup.query.filter_by(owner_user_id=uid).delete(synchronize_session=False)
            # Delete all assets (files deleted below after new ones extracted)
            for a in Asset.query.filter_by(user_id=uid).all():
                db.session.delete(a)
            for f in AssetFolder.query.filter_by(user_id=uid).all():
                db.session.delete(f)
            # Old picture system
            old_pic_ids = [p.id for p in Picture.query.filter_by(user_id=uid).all()]
            if old_pic_ids:
                SectionImage.query.filter(SectionImage.picture_id.in_(old_pic_ids)).delete(synchronize_session=False)
                Picture.query.filter_by(user_id=uid).delete(synchronize_session=False)
            Folder.query.filter_by(user_id=uid).delete(synchronize_session=False)
            db.session.flush()

            # ── ID maps ───────────────────────────────────────────────────────
            website_map = {};
            folder_map = {};
            page_map = {}
            sg_map = {};
            row_map = {};
            col_map = {};
            sec_map = {}
            cal_map = {};
            cal_sub_map = {};
            agent_map = {}
            af_map = {};
            asset_map = {}
            sgt_map = {};
            st_map = {};
            pt_map = {}
            pg_map = {};
            sa_map = {};
            pic_folder_map = {};
            pic_map = {}

            # ── Websites ──────────────────────────────────────────────────────
            for wd in data.get('websites', []):
                w = Website(user_id=uid, name=wd['name'], description=wd.get('description'),
                            is_draft=wd.get('is_draft', False),
                            background_color=wd.get('background_color', '#ffffff'),
                            text_color=wd.get('text_color', '#000000'),
                            background_image_url=wd.get('background_image_url'),
                            background_image_repeat=wd.get('background_image_repeat', False),
                            background_image_repeat_x=wd.get('background_image_repeat_x', False),
                            background_image_mobile_cover=wd.get('background_image_mobile_cover', False),
                            background_image_zoom=wd.get('background_image_zoom', 100),
                            public_navbar_items=wd.get('public_navbar_items') or [],
                            public_navbar_style=wd.get('public_navbar_style') or {},
                            forum_enabled=wd.get('forum_enabled', False),
                            forum_show_in_navbar=wd.get('forum_show_in_navbar', True),
                            forum_require_login_to_view=wd.get('forum_require_login_to_view', False),
                            forum_require_login_to_post=wd.get('forum_require_login_to_post', True),
                            forum_title=wd.get('forum_title', 'Forum'),
                            forum_description=wd.get('forum_description'),
                            forum_account_verification_enabled=wd.get('forum_account_verification_enabled', False),
                            forum_allow_unverified_login=wd.get('forum_allow_unverified_login', False))
                db.session.add(w);
                db.session.flush()
                website_map[wd['id']] = w.id

            # ── Page folders ──────────────────────────────────────────────────
            for fd in data.get('page_folders', []):
                new_wid = website_map.get(fd['website_id'])
                if not new_wid:
                    continue
                f = PageFolder(website_id=new_wid, name=fd['name'],
                               sort_order=fd.get('sort_order', 0))
                db.session.add(f);
                db.session.flush()
                folder_map[fd['id']] = f.id

            # ── Pages ─────────────────────────────────────────────────────────
            for pd in data.get('pages', []):
                new_wid = website_map.get(pd['website_id'])
                if not new_wid:
                    continue
                p = PublicPageContent(
                    website_id=new_wid,
                    page_folder_id=folder_map.get(pd['page_folder_id']) if pd.get('page_folder_id') else None,
                    folder_sort_order=pd.get('folder_sort_order', 0),
                    name=pd['name'], description=pd.get('description'),
                    sort_order=pd.get('sort_order', 0), slug=pd.get('slug', 'page'),
                    site_active_status=pd.get('site_active_status', False),
                    background_color=pd.get('background_color', '#ffffff'),
                    text_color=pd.get('text_color', '#000000'),
                    custom_code=pd.get('custom_code'))
                db.session.add(p);
                db.session.flush()
                page_map[pd['id']] = p.id

            # ── Section groups ─────────────────────────────────────────────────
            for gd in data.get('section_groups', []):
                new_pid = page_map.get(gd['page_content_id'])
                if not new_pid:
                    continue
                g = SectionGroup(page_content_id=new_pid,
                                 name=gd.get('name', 'Section Group'),
                                 anchor_slug=gd.get('anchor_slug'),
                                 group_order=gd.get('group_order', 0),
                                 background_color=gd.get('background_color', 'transparent'),
                                 background_opacity=gd.get('background_opacity', 1),
                                 padding=gd.get('padding', 20),
                                 border_radius=gd.get('border_radius', 0),
                                 max_width=gd.get('max_width'),
                                 background_image_url=gd.get('background_image_url'),
                                 background_image_size=gd.get('background_image_size', 'cover'),
                                 background_image_position=gd.get('background_image_position', 'center'),
                                 background_overlay_color=gd.get('background_overlay_color', 'transparent'),
                                 background_overlay_opacity=gd.get('background_overlay_opacity', 0))
                db.session.add(g);
                db.session.flush()
                sg_map[gd['id']] = g.id

            # ── Rows ──────────────────────────────────────────────────────────
            for rd in data.get('rows', []):
                new_pid = page_map.get(rd['page_content_id'])
                if not new_pid:
                    continue
                r = Row(page_content_id=new_pid, row_number=rd['row_number'],
                        section_group_id=sg_map.get(rd['section_group_id']) if rd.get('section_group_id') else None)
                db.session.add(r);
                db.session.flush()
                row_map[rd['id']] = r.id

            # ── Sections (no column yet) ───────────────────────────────────────
            for sd in data.get('sections', []):
                new_pid = page_map.get(sd['page_content_id'])
                if not new_pid:
                    continue
                s = PageSection(section_type=sd['section_type'], order=sd.get('order'),
                                content=sd.get('content'), page_content_id=new_pid,
                                custom_code=sd.get('custom_code'), label=sd.get('label'))
                db.session.add(s);
                db.session.flush()
                sec_map[sd['id']] = s.id

            # ── Columns (links rows ↔ sections) ───────────────────────────────
            for cd in data.get('columns', []):
                new_rid = row_map.get(cd['row_id'])
                if not new_rid:
                    continue
                c = Column(row_id=new_rid, column_number=cd['column_number'],
                           section_id=sec_map.get(cd['section_id']) if cd.get('section_id') else None,
                           width=cd.get('width'))
                db.session.add(c);
                db.session.flush()
                col_map[cd['id']] = c.id

            # ── Asset folders ─────────────────────────────────────────────────
            for fd in data.get('asset_folders', []):
                af = AssetFolder(name=fd['name'], user_id=uid,
                                 asset_type=fd.get('asset_type'))
                db.session.add(af);
                db.session.flush()
                af_map[fd['id']] = af.id

            # ── Assets ────────────────────────────────────────────────────────
            old_url_prefix = f'/static/uploads/{old_uid}/assets/'
            new_url_prefix = f'/static/uploads/{uid}/assets/'

            for ad in data.get('assets', []):
                new_url = (ad.get('url') or '').replace(old_url_prefix, new_url_prefix)
                new_thumb = (ad.get('thumbnail_url') or '').replace(old_url_prefix, new_url_prefix)
                a = Asset(user_id=uid,
                          folder_id=af_map.get(ad['folder_id']) if ad.get('folder_id') else None,
                          original_filename=ad['original_filename'],
                          stored_filename=ad['stored_filename'],
                          original_stored_filename=ad.get('original_stored_filename'),
                          url=new_url, thumbnail_url=new_thumb or None,
                          asset_type=ad.get('asset_type', 'misc'),
                          mime_type=ad.get('mime_type'), extension=ad.get('extension'),
                          file_size=ad.get('file_size', 0))
                db.session.add(a);
                db.session.flush()
                asset_map[ad['id']] = a.id

            # ── Section assets ─────────────────────────────────────────────────
            for sad in data.get('section_assets', []):
                new_sid = sec_map.get(sad['section_id'])
                new_aid = asset_map.get(sad['asset_id'])
                if new_sid and new_aid:
                    db.session.add(SectionAsset(section_id=new_sid, asset_id=new_aid,
                                                usage_type=sad.get('usage_type'),
                                                order=sad.get('order', 0)))

            # ── Old picture system ─────────────────────────────────────────────
            for fd in data.get('picture_folders', []):
                pf = Folder(name=fd['name'], user_id=uid)
                db.session.add(pf);
                db.session.flush()
                pic_folder_map[fd['id']] = pf.id

            for pd in data.get('pictures', []):
                new_url = (pd.get('url') or '').replace(old_url_prefix, new_url_prefix)
                new_thumb = (pd.get('thumbnail_url') or '').replace(old_url_prefix, new_url_prefix)
                new_orig = (pd.get('original_url') or '').replace(old_url_prefix, new_url_prefix)
                pic = Picture(url=new_url, thumbnail_url=new_thumb or None,
                              original_url=new_orig or None, user_id=uid,
                              folder_id=pic_folder_map.get(pd['folder_id']) if pd.get('folder_id') else None)
                db.session.add(pic);
                db.session.flush()
                pic_map[pd['id']] = pic.id

            for sid_d in data.get('section_images', []):
                new_sid = sec_map.get(sid_d['section_id'])
                new_pid = pic_map.get(sid_d['picture_id'])
                if new_sid and new_pid:
                    db.session.add(SectionImage(section_id=new_sid, picture_id=new_pid,
                                                order=sid_d.get('order', 0)))

            # ── Calendars ─────────────────────────────────────────────────────
            for cd in data.get('calendars', []):
                new_wid = website_map.get(cd['website_id'])
                if not new_wid:
                    continue
                cal = Calendar(name=cd['name'], description=cd.get('description'),
                               website_id=new_wid, styles=cd.get('styles'))
                db.session.add(cal);
                db.session.flush()
                cal_map[cd['id']] = cal.id

            for ed in data.get('calendar_events', []):
                new_cid = cal_map.get(ed['calendar_id'])
                if not new_cid:
                    continue
                ev = CalendarEvent(
                    title=ed['title'], description=ed.get('description'),
                    start=datetime.fromisoformat(ed['start']),
                    end=datetime.fromisoformat(ed['end']) if ed.get('end') else None,
                    background_color=ed.get('background_color'),
                    calendar_id=new_cid,
                    section_id=sec_map.get(ed['section_id']) if ed.get('section_id') else None,
                    source='local')
                db.session.add(ev)

            for sd in data.get('calendar_subscriptions', []):
                new_cid = cal_map.get(sd['calendar_id'])
                if not new_cid:
                    continue
                cs = CalendarSubscription(calendar_id=new_cid, name=sd.get('name'), url=sd['url'])
                db.session.add(cs);
                db.session.flush()
                cal_sub_map[sd['id']] = cs.id

            # ── AI agents ─────────────────────────────────────────────────────
            for ad in data.get('ai_agents', []):
                new_wid = website_map.get(ad['website_id'])
                if not new_wid:
                    continue
                ag = AIAgent(website_id=new_wid, name=ad['name'],
                             provider=ad.get('provider', 'openai_compatible'),
                             api_url=ad.get('api_url'), api_key=ad.get('api_key'),
                             model=ad.get('model'), system_prompt=ad.get('system_prompt'),
                             capabilities=ad.get('capabilities', 'chat'))
                db.session.add(ag);
                db.session.flush()
                agent_map[ad['id']] = ag.id

            # ── Templates ─────────────────────────────────────────────────────
            for td in data.get('section_group_templates', []):
                new_wid = website_map.get(td['website_id'])
                if not new_wid:
                    continue
                db.session.add(SectionGroupTemplate(
                    website_id=new_wid, name=td['name'],
                    description=td.get('description'), template_data=td.get('template_data', {}),
                    row_count=td.get('row_count', 0), section_count=td.get('section_count', 0)))

            for td in data.get('section_templates', []):
                new_wid = website_map.get(td['website_id'])
                if not new_wid:
                    continue
                db.session.add(SectionTemplate(
                    website_id=new_wid, name=td['name'],
                    section_type=td['section_type'], content=td.get('content'),
                    custom_code=td.get('custom_code')))

            for td in data.get('page_templates', []):
                new_wid = website_map.get(td['website_id'])
                if not new_wid:
                    continue
                db.session.add(PageTemplate(
                    website_id=new_wid, name=td['name'],
                    description=td.get('description'), template_data=td.get('template_data', {}),
                    group_count=td.get('group_count', 0), section_count=td.get('section_count', 0)))

            # ── Permission groups ──────────────────────────────────────────────
            for gd in data.get('permission_groups', []):
                pg = PermissionGroup(owner_user_id=uid, name=gd['name'],
                                     description=gd.get('description'),
                                     permissions=gd.get('permissions') or {})
                db.session.add(pg);
                db.session.flush()
                pg_map[gd['id']] = pg.id

            # ── Sub-admins ─────────────────────────────────────────────────────
            for ud in data.get('sub_admins', []):
                sub = User(username=ud['username'], email=ud['email'],
                           password_hash=ud['password_hash'],
                           parent_user_id=uid,
                           permission_group_id=pg_map.get(ud['permission_group_id']) if ud.get(
                               'permission_group_id') else None,
                           permissions=ud.get('permissions') or {},
                           _is_active=ud.get('_is_active', True))
                db.session.add(sub);
                db.session.flush()
                sa_map[ud['id']] = sub.id

            # ── Remap ID-based permission keys ────────────────────────────────
            def _remap_perm_ids(perms):
                """Return a copy of a permissions dict with all stored IDs
                remapped through the maps built during this import."""
                if not perms:
                    return perms
                p = dict(perms)
                def _remap_list(key, id_map):
                    lst = p.get(key)
                    if lst:
                        remapped = [id_map[i] for i in lst if i in id_map]
                        p[key] = remapped if remapped else None
                _remap_list('pages.allowed_ids',          page_map)
                _remap_list('sections.allowed_ids',       sec_map)
                _remap_list('groups.allowed_ids',         sg_map)
                _remap_list('assets.allowed_folder_ids',  af_map)
                # page_folder_perms: {str(folder_id): "full"|[actions]}
                pfp = p.get('page_folder_perms')
                if pfp:
                    new_pfp = {}
                    for old_fid_str, val in pfp.items():
                        try:
                            new_fid = folder_map.get(int(old_fid_str))
                        except (ValueError, TypeError):
                            continue
                        if new_fid:
                            new_pfp[str(new_fid)] = val
                    p['page_folder_perms'] = new_pfp or None
                return p

            # Apply remapping to permission groups
            for pg in PermissionGroup.query.filter(
                    PermissionGroup.id.in_(list(pg_map.values()))).all():
                pg.permissions = _remap_perm_ids(pg.permissions)

            # Apply remapping to sub-admin individual permissions
            for sub in User.query.filter(
                    User.id.in_(list(sa_map.values()))).all():
                sub.permissions = _remap_perm_ids(sub.permissions)

            # Restore last_edited_at on pages (user ID is not remapped — left null)
            old_page_edited = {pd['id']: pd.get('last_edited_at') for pd in data.get('pages', [])}
            for old_pid, last_edited_str in old_page_edited.items():
                new_pid = page_map.get(old_pid)
                if new_pid and last_edited_str:
                    p_obj = PublicPageContent.query.get(new_pid)
                    if p_obj:
                        try:
                            p_obj.last_edited_at = datetime.fromisoformat(last_edited_str)
                        except Exception:
                            pass

            # ── Rewrite section IDs and asset URLs in section content ──────────
            old_sec_keys = list(sec_map.keys())
            all_new_sections = PageSection.query.filter(
                PageSection.id.in_(list(sec_map.values()))
            ).all()
            for s in all_new_sections:
                changed = False
                # Rewrite content JSON (URLs + #section-{id} anchors)
                if s.content is not None:
                    raw = json.dumps(s.content)
                    raw2 = raw.replace(old_url_prefix, new_url_prefix)
                    for old_sid, new_sid in sec_map.items():
                        raw2 = raw2.replace(f'#section-{old_sid}', f'#section-{new_sid}')
                    if raw2 != raw:
                        s.content = json.loads(raw2)
                        changed = True
                # Rewrite custom_code
                if s.custom_code:
                    cc = s.custom_code.replace(old_url_prefix, new_url_prefix)
                    for old_sid, new_sid in sec_map.items():
                        cc = cc.replace(f'#section-{old_sid}', f'#section-{new_sid}')
                    if cc != s.custom_code:
                        s.custom_code = cc
                        changed = True
                if changed:
                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(s, 'content')

            # Rewrite page custom_code
            for p in PublicPageContent.query.filter(
                    PublicPageContent.id.in_(list(page_map.values()))
            ).all():
                if p.custom_code:
                    cc = p.custom_code.replace(old_url_prefix, new_url_prefix)
                    for old_sid, new_sid in sec_map.items():
                        cc = cc.replace(f'#section-{old_sid}', f'#section-{new_sid}')
                    if cc != p.custom_code:
                        p.custom_code = cc

            db.session.commit()

            # ── Extract asset files ────────────────────────────────────────────
            new_assets_dir = os.path.join(uploads_folder, str(uid), 'assets')
            os.makedirs(new_assets_dir, exist_ok=True)
            # Clear old files
            for fname in os.listdir(new_assets_dir):
                fpath = os.path.join(new_assets_dir, fname)
                if os.path.isfile(fpath):
                    os.remove(fpath)
            # Extract new files
            for name in zf.namelist():
                if name.startswith('assets/') and not name.endswith('/'):
                    fname = name[len('assets/'):]
                    with zf.open(name) as src, open(os.path.join(new_assets_dir, fname), 'wb') as dst:
                        shutil.copyfileobj(src, dst)

    except zipfile.BadZipFile:
        return _utf8_json({'success': False, 'error': 'Invalid ZIP file'}, 400)
    except Exception as e:
        db.session.rollback()
        app.logger.exception('import_backup error')
        return _utf8_json({'success': False, 'error': str(e)}, 500)

    return _utf8_json({'success': True})


def render_public_page(website, page, is_preview=False):
    sections = PageSection.query.filter_by(
        page_content_id=page.id
    ).order_by(PageSection.order).all()

    pictures_by_section = {}
    music_by_section = {}
    videos_by_section = {}

    for section in sections:
        section_assets = (
            db.session.query(Asset.url)
            .join(SectionAsset, Asset.id == SectionAsset.asset_id)
            .filter(
                SectionAsset.section_id == section.id,
                Asset.asset_type == 'image'
            )
            .order_by(SectionAsset.order)
            .all()
        )

        pictures_by_section[section.id] = [asset.url for asset in section_assets]
        music_assets = (
            db.session.query(Asset, SectionAsset)
            .join(SectionAsset, Asset.id == SectionAsset.asset_id)
            .filter(
                SectionAsset.section_id == section.id,
                Asset.asset_type == 'audio'
            )
            .order_by(SectionAsset.order)
            .all()
        )

        music_by_section[section.id] = [
            {
                'id': asset.id,
                'asset_id': asset.id,
                'link_id': link.id,
                'url': asset.url,
                'mime_type': asset.mime_type or 'audio/mpeg',
                'filename': asset.original_filename,
                'extension': asset.extension,
                'file_size_label': format_bytes(asset.file_size),
                'play_count': asset.play_count or 0,
                'unique_play_count': asset.unique_play_count or 0,
                'last_played_at': asset.last_played_at.isoformat() if asset.last_played_at else None
            }
            for asset, link in music_assets
        ]
        video_assets = (
            db.session.query(Asset, SectionAsset)
            .join(SectionAsset, Asset.id == SectionAsset.asset_id)
            .filter(
                SectionAsset.section_id == section.id,
                Asset.asset_type == 'video'
            )
            .order_by(SectionAsset.order)
            .all()
        )

        videos_by_section[section.id] = [
            {
                'id': asset.id,
                'asset_id': asset.id,
                'link_id': link.id,
                'url': asset.url,
                'thumbnail_url': asset.thumbnail_url or '',
                'mime_type': asset.mime_type or 'video/mp4',
                'filename': asset.original_filename,
                'extension': asset.extension,
                'file_size_label': format_bytes(asset.file_size),
                'play_count': asset.play_count or 0,
                'unique_play_count': asset.unique_play_count or 0,
                'last_played_at': asset.last_played_at.isoformat() if asset.last_played_at else None
            }
            for asset, link in video_assets
        ]

    comments_by_section = {}

    for section in sections:
        if section.section_type != 'comments':
            continue

        comment_settings = section.content or {}
        comments_per_page = int(comment_settings.get('comments_per_page') or 25)

        comments = PageComment.query.filter_by(
            section_id=section.id,
            is_hidden=False,
            is_approved=True
        ).order_by(
            PageComment.created_at.desc()
        ).limit(comments_per_page).all()

        comments_by_section[section.id] = comments

    section_groups = SectionGroup.query.filter_by(
        page_content_id=page.id
    ).order_by(SectionGroup.group_order).all()

    # For draft website previews, rewrite navbar URLs from public slugs
    # (/home, /about …) to admin preview routes so every link stays within
    # the draft.  We also fix current_page_url so active-link highlighting
    # still works, and expose the rewritten items + a home URL to the navbar
    # template component.
    preview_navbar_items = None
    preview_home_url = None
    if is_preview and website.is_draft:
        all_pages = PublicPageContent.query.filter_by(website_id=website.id).all()
        slug_to_preview = {
            '/' + p.slug: url_for('preview_page', website_id=website.id, page_id=p.id)
            for p in all_pages
        }

        def _rewrite_url(url):
            if not url or not url.startswith('/'):
                return url
            base = url.split('#')[0]
            preview = slug_to_preview.get(base)
            if not preview:
                return url
            frag = url[len(base):]  # '#anchor' or ''
            return preview + frag

        def _rewrite_items(items):
            result = []
            for itm in (items or []):
                itm = dict(itm)
                if itm.get('type') == 'link':
                    itm['url'] = _rewrite_url(itm.get('url', ''))
                elif itm.get('type') == 'group':
                    itm['children'] = _rewrite_items(itm.get('children', []))
                result.append(itm)
            return result

        preview_navbar_items = _rewrite_items(website.public_navbar_items or [])
        preview_home_url = slug_to_preview.get('/home') or (
            url_for('preview_page', website_id=website.id, page_id=all_pages[0].id)
            if all_pages else '#'
        )

    current_page_url = (
        url_for('preview_page', website_id=website.id, page_id=page.id)
        if (is_preview and website.is_draft)
        else url_for('public_page_by_slug', page_slug=page.slug)
    )

    public_page_content = {
        'page_id': page.id,
        'page_slug': page.slug,
        'current_page_url': current_page_url,
        'sections': [
            {**s.to_dict(),
             'custom_code': _scope_section_css(s.custom_code, s.id) if s.custom_code else ''}
            for s in sections if s.column and s.column.row
        ],
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
                'max_width': group.max_width,

                'background_image_url': group.background_image_url,
                'background_image_size': group.background_image_size or 'cover',
                'background_image_position': group.background_image_position or 'center',
                'background_overlay_color': group.background_overlay_color or 'transparent',
                'background_overlay_opacity': group.background_overlay_opacity or 0
            }
            for group in section_groups
        ],
        'pictures_by_section': pictures_by_section,
        'music_by_section': music_by_section,
        'videos_by_section': videos_by_section,
        'comments_by_section': comments_by_section,
        'public_user': get_public_user(),
        'is_preview': is_preview,
        'custom_code': page.custom_code or '',
    }

    html = render_template(
        'public.html',
        website=website,
        content=public_page_content,
        preview_navbar_items=preview_navbar_items,
        preview_home_url=preview_home_url,
    )

    response = make_response(html)

    if should_track_page_visit(is_preview=is_preview):
        visitor_id = request.cookies.get('uwebia_visitor_id')

        if not visitor_id:
            visitor_id = uuid.uuid4().hex

            response.set_cookie(
                'uwebia_visitor_id',
                visitor_id,
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite='Lax'
            )

        track_page_visit(website, page, visitor_id)

    return response


@app.route('/asset/<int:asset_id>/track-play', methods=['POST'])
def track_asset_play(asset_id):
    asset = Asset.query.get_or_404(asset_id)

    if asset.asset_type not in ['audio', 'video']:
        return jsonify({
            'success': False,
            'message': 'Only audio and video assets can be tracked.'
        }), 400

    visitor_id, should_set_cookie = get_or_create_asset_visitor_id()
    visitor_id_hash = hash_asset_visitor_id(visitor_id)

    play_record = AssetPlay.query.filter_by(
        asset_id=asset.id,
        visitor_id_hash=visitor_id_hash
    ).first()

    is_unique_play = play_record is None

    if play_record:
        play_record.play_count = (play_record.play_count or 0) + 1
        play_record.last_played_at = datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        play_record = AssetPlay(
            asset_id=asset.id,
            visitor_id_hash=visitor_id_hash,
            first_played_at=datetime.now(timezone.utc).replace(tzinfo=None),
            last_played_at=datetime.now(timezone.utc).replace(tzinfo=None),
            play_count=1
        )

        db.session.add(play_record)
        asset.unique_play_count = (asset.unique_play_count or 0) + 1

    asset.play_count = (asset.play_count or 0) + 1
    asset.last_played_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.session.commit()

    response = jsonify({
        'success': True,
        'asset_id': asset.id,
        'play_count': asset.play_count or 0,
        'unique_play_count': asset.unique_play_count or 0,
        'is_unique_play': is_unique_play,
        'last_played_at': asset.last_played_at.isoformat()
    })

    if should_set_cookie:
        response.set_cookie(
            'uwebia_asset_visitor_id',
            visitor_id,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite='Lax'
        )

    return response


@app.route('/admin/dashboard/analytics/geoip/backfill', methods=['POST'])
@login_required
@require_perm('analytics.geoip')
def backfill_geoip_locations():
    websites = Website.query.filter_by(user_id=current_user.root_user_id).all()
    website_ids = [website.id for website in websites]

    if not website_ids:
        return jsonify({
            'success': True,
            'updated_count': 0,
            'message': 'No websites found.'
        })

    website_by_id = {website.id: website for website in websites}

    visits = PageVisit.query.filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.ip_address.isnot(None),
        PageVisit.ip_address != '',
        PageVisit.country.is_(None)
    ).limit(1000).all()

    updated_count = 0

    for visit in visits:
        website = website_by_id.get(visit.website_id)

        if not website:
            continue

        location = lookup_ip_location_for_website(website, visit.ip_address)

        if not location:
            continue

        visit.country = location.get('country')
        visit.country_iso = location.get('country_iso')
        visit.region = location.get('region')
        visit.city = location.get('city')
        visit.latitude = location.get('latitude')
        visit.longitude = location.get('longitude')
        visit.location_source = location.get('location_source')

        updated_count += 1

    db.session.commit()

    return jsonify({
        'success': True,
        'updated_count': updated_count,
        'message': f'Backfilled location data for {updated_count} visits.'
    })


@app.route('/admin/dashboard/analytics')
@login_required
def analytics_page():
    websites = Website.query.filter_by(user_id=current_user.root_user_id).all()

    website_ids = [website.id for website in websites]
    csrf_token = generate_csrf()

    if not website_ids:
        return render_template(
            'analytics.html',
            websites=[],
            total_page_views=0,
            total_unique_visitors=0,
            visits_by_day=[],
            page_stats=[],
            referrer_stats=[],
            analytics_settings=get_analytics_settings_for_user(current_user.id),
            country_stats=[],
            city_stats=[],
            asn_stats=[],
            days=30,
            recent_visits=[],
            calendar_subscriber_summary={
                'active_7_days': 0,
                'active_30_days': 0,
                'total_seen': 0,
                'total_requests': 0,
                'top_calendars': []
            },
            csrf_token=csrf_token
        )

    days = 30
    start_date = get_utc_start_for_user_local_days(days, current_user)

    total_page_views = PageVisit.query.filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date
    ).count()

    total_unique_visitors = db.session.query(
        func.count(func.distinct(PageVisit.visitor_id))
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date
    ).scalar() or 0

    visits_for_chart = PageVisit.query.filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date
    ).all()

    user_timezone = get_user_timezone(current_user)

    visits_by_day_map = {}

    for visit in visits_for_chart:
        visited_at = visit.visited_at

        if visited_at.tzinfo is None:
            visited_at = pytz.utc.localize(visited_at)

        local_day = visited_at.astimezone(user_timezone).date().isoformat()

        if local_day not in visits_by_day_map:
            visits_by_day_map[local_day] = {
                'date': local_day,
                'page_views': 0,
                'visitor_ids': set()
            }

        visits_by_day_map[local_day]['page_views'] += 1
        visits_by_day_map[local_day]['visitor_ids'].add(visit.visitor_id)

    visits_by_day = []

    local_today = datetime.now(user_timezone).date()
    local_start_day = local_today - timedelta(days=days - 1)

    for i in range(days):
        day = (local_start_day + timedelta(days=i)).isoformat()
        item = visits_by_day_map.get(day)
        day_date = datetime.strptime(day, '%Y-%m-%d').date()

        visits_by_day.append({
            'date': day,
            'label': day_date.strftime('%b %d'),
            'page_views': item['page_views'] if item else 0,
            'unique_visitors': len(item['visitor_ids']) if item else 0
        })

    page_stats = db.session.query(
        PublicPageContent.id,
        PublicPageContent.name,
        PublicPageContent.slug,
        func.count(PageVisit.id).label('page_views'),
        func.count(func.distinct(PageVisit.visitor_id)).label('unique_visitors')
    ).join(
        PageVisit,
        PageVisit.page_id == PublicPageContent.id
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date
    ).group_by(
        PublicPageContent.id
    ).order_by(
        func.count(PageVisit.id).desc()
    ).limit(20).all()

    referrer_stats = db.session.query(
        PageVisit.referrer,
        func.count(PageVisit.id).label('visits')
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date,
        PageVisit.referrer.isnot(None),
        PageVisit.referrer != ''
    ).group_by(
        PageVisit.referrer
    ).order_by(
        func.count(PageVisit.id).desc()
    ).limit(20).all()

    analytics_settings = get_analytics_settings_for_user(current_user.id)

    country_stats = db.session.query(
        PageVisit.country,
        PageVisit.country_iso,
        func.count(PageVisit.id).label('visits'),
        func.count(func.distinct(PageVisit.visitor_id)).label('unique_visitors')
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date,
        PageVisit.country.isnot(None),
        PageVisit.country != ''
    ).group_by(
        PageVisit.country,
        PageVisit.country_iso
    ).order_by(
        func.count(PageVisit.id).desc()
    ).limit(20).all()

    city_stats = db.session.query(
        PageVisit.city,
        PageVisit.region,
        PageVisit.country,
        func.count(PageVisit.id).label('visits'),
        func.count(func.distinct(PageVisit.visitor_id)).label('unique_visitors')
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date,
        PageVisit.city.isnot(None),
        PageVisit.city != ''
    ).group_by(
        PageVisit.city,
        PageVisit.region,
        PageVisit.country
    ).order_by(
        func.count(PageVisit.id).desc()
    ).limit(20).all()

    asn_stats = db.session.query(
        PageVisit.asn_number,
        PageVisit.asn_organization,
        func.count(PageVisit.id).label('visits'),
        func.count(func.distinct(PageVisit.visitor_id)).label('unique_visitors')
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date,
        PageVisit.asn_number.isnot(None)
    ).group_by(
        PageVisit.asn_number,
        PageVisit.asn_organization
    ).order_by(
        func.count(PageVisit.id).desc()
    ).limit(20).all()

    recent_visit_rows = db.session.query(
        PageVisit,
        PublicPageContent
    ).join(
        PublicPageContent,
        PageVisit.page_id == PublicPageContent.id
    ).filter(
        PageVisit.website_id.in_(website_ids),
        PageVisit.visited_at >= start_date
    ).order_by(
        PageVisit.visited_at.desc()
    ).limit(20).all()

    recent_visits = []

    for visit, page in recent_visit_rows:
        recent_visits.append({
            'page_name': page.name if page else 'Unknown Page',
            'path': visit.path or '',
            'visited_at': format_user_datetime(visit.visited_at, current_user),
            'ip_address': visit.ip_address,
            'country': visit.country,
            'city': visit.city,

            'asn_organization': visit.asn_organization
        })

    calendar_subscriber_summary = get_calendar_subscriber_summary_for_websites(website_ids)

    return render_template(
        'analytics.html',
        websites=websites,
        total_page_views=total_page_views,
        total_unique_visitors=total_unique_visitors,
        visits_by_day=visits_by_day,
        page_stats=page_stats,
        referrer_stats=referrer_stats,
        country_stats=country_stats,
        city_stats=city_stats,
        analytics_settings=analytics_settings,
        days=days,
        asn_stats=asn_stats,
        recent_visits=recent_visits,
        calendar_subscriber_summary=calendar_subscriber_summary,
        csrf_token=csrf_token
    )


@app.route('/')
def home_page():
    website = get_live_website()

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


# @app.route('/preview_page/<int:website_id>/<int:page_id>')
# @login_required
# def preview_page(website_id, page_id):
#     # Use db.session.get for SQLAlchemy 2.0 compatibility
#     website = db.session.get(Website, website_id)
#     if not website or not is_owner(website):
#         return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 404
#
#     content = PublicPageContent.query.filter_by(website_id=website_id, id=page_id).first()
#
#     if content is None:
#         return jsonify({'status': 'error', 'message': 'Public page content not found'})
#
#     sections = PageSection.query.filter_by(page_content_id=content.id).order_by(PageSection.order).all()
#
#     pictures_by_section = {}
#     for section in sections:
#         # NEW LOGIC: Join SectionImage and Picture to get the URLs for this specific section
#         section_assets = (
#             db.session.query(Asset.url)
#             .join(SectionAsset, Asset.id == SectionAsset.asset_id)
#             .filter(
#                 SectionAsset.section_id == section.id,
#                 Asset.asset_type == 'image'
#             )
#             .order_by(SectionAsset.order)
#             .all()
#         )
#
#         pictures_by_section[section.id] = [asset.url for asset in section_assets]
#
#     sections_dict = [section.to_dict() for section in sections]
#
#     # public_page_content = {
#     #     'page_id': content.id,
#     #     'sections': sections_dict,
#     #     'pictures_by_section': pictures_by_section,
#     #     'background_color': content.background_color,
#     #     'text_color': content.text_color
#     # }
#     #
#     # return render_template('public.html', content=public_page_content)
#
#     section_groups = SectionGroup.query.filter_by(
#         page_content_id=content.id
#     ).order_by(SectionGroup.group_order).all()
#
#     public_page_content = {
#         'page_id': content.id,
#         'sections': sections_dict,
#         'page_slug': content.slug,
#         'current_page_url': url_for('public_page_by_slug', page_slug=content.slug),
#         'groups': [
#     {
#         'id': group.id,
#         'name': group.name,
#         'anchor_slug': group.anchor_slug,
#         'group_order': group.group_order,
#
#         'background_color': group.background_color or 'transparent',
#         'background_opacity': group.background_opacity,
#
#         'padding': group.padding,
#         'border_radius': group.border_radius,
#
#         'background_image_url': group.background_image_url,
#         'background_image_size': group.background_image_size or 'cover',
#         'background_image_position': group.background_image_position or 'center',
#         'background_overlay_color': group.background_overlay_color or 'transparent',
#         'background_overlay_opacity': group.background_overlay_opacity or 0
#     }
#     for group in section_groups
# ],
#         'pictures_by_section': pictures_by_section,
#         'is_preview': True
#     }
#
#     return render_template(
#         'public.html',
#         website=website,
#         content=public_page_content
#     )

@app.route('/preview_page/<int:website_id>/<int:page_id>')
@login_required
def preview_page(website_id, page_id):
    website = db.session.get(Website, website_id)

    if not website or not is_owner(website):
        return jsonify({'status': 'error', 'message': 'Unauthorized access'}), 404

    page = PublicPageContent.query.filter_by(
        website_id=website_id,
        id=page_id
    ).first_or_404()

    return render_public_page(website, page, is_preview=True)


@app.route('/section/<int:section_id>/comments')
def get_public_section_comments(section_id):
    section = PageSection.query.get_or_404(section_id)

    if section.section_type != 'comments':
        return jsonify({
            'success': False,
            'message': 'This section is not a comments section.'
        }), 400

    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)

    if not page.site_active_status:
        return jsonify({
            'success': False,
            'message': 'This page is not published.'
        }), 404

    settings = section.content or {}

    if not settings.get('enabled', True):
        return jsonify({
            'success': False,
            'message': 'Comments are disabled.'
        }), 403

    page_number = request.args.get('page', 1, type=int)
    per_page = int(settings.get('comments_per_page') or 25)
    per_page = max(5, min(per_page, 100))

    pagination = PageComment.query.filter_by(
        section_id=section.id,
        is_hidden=False,
        is_approved=True
    ).order_by(
        PageComment.created_at.desc()
    ).paginate(
        page=page_number,
        per_page=per_page,
        error_out=False
    )
    public_user = get_public_user()

    return jsonify({
        'success': True,
        'comments': [
            {
                'id': comment.id,
                'display_name': comment.display_name,
                'body': comment.body,
                'created_at': comment.created_at.strftime('%b %d, %Y %I:%M %p'),
                'like_count': comment.like_count_cached or 0,
                'liked_by_current_user': comment.user_has_liked(public_user)
            }
            for comment in pagination.items
        ],
        'pagination': {
            'page': pagination.page,
            'pages': pagination.pages,
            'has_prev': pagination.has_prev,
            'has_next': pagination.has_next,
            'prev_num': pagination.prev_num,
            'next_num': pagination.next_num,
            'total': pagination.total
        }
    })


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

    if not website or not is_owner(website):
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
    text_max_width = form_data.get('text_max_width', '0')

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
        'box_shadow': box_shadow,
        'text_max_width': text_max_width
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
@require_perm('appearance.navbar')
def edit_public_navbar(website_id):
    website = Website.query.get_or_404(website_id)

    if not is_owner(website):
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
@require_perm('appearance.navbar')
def edit_public_navbar_style(website_id):
    website = Website.query.get_or_404(website_id)

    if not is_owner(website):
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 403

    data = request.get_json() or {}

    try:
        margin = int(data.get('margin') or 0)
    except ValueError:
        margin = 0

    margin = max(0, min(80, margin))

    dropdown_mode = (data.get('dropdown_mode') or 'dropdown').strip()

    # Normalize possible variants
    if dropdown_mode in ['side-panel', 'sidepanel', 'side_panel']:
        dropdown_mode = 'side_panel'
    else:
        dropdown_mode = 'dropdown'

    side_panel_use_navbar_background = bool(
        data.get('side_panel_use_navbar_background', False)
    )

    existing_style = website.public_navbar_style or {}

    website.public_navbar_style = {
        **existing_style,
        'title': data.get('title', website.name),
        'title_font_family': data.get('title_font_family', 'inherit'),
        'title_font_size': data.get('title_font_size', 16),
        'title_bold': data.get('title_bold', True),
        'icon_url': data.get('icon_url', ''),
        'background': data.get('background', 'rgba(20,20,20,0.9)'),
        'text_color': data.get('text_color', '#ffffff'),
        'opacity': data.get('opacity', 0.9),
        'blur': data.get('blur', 14),
        'border_radius': data.get('border_radius', 0),
        'shadow': data.get('shadow', True),
        'sticky': data.get('sticky', True),
        'title_alignment': data.get('title_alignment', 'left'),
        'margin': margin,
        'dropdown_mode': dropdown_mode,
        'side_panel_use_navbar_background': side_panel_use_navbar_background,
    }

    db.session.commit()

    return jsonify({
        'success': True,
        'public_navbar_style': website.public_navbar_style
    })


@app.route('/upload_public_navbar_icon/<int:website_id>', methods=['POST'])
@login_required
@require_perm('appearance.navbar')
def upload_public_navbar_icon(website_id):
    website = Website.query.get_or_404(website_id)

    if not is_owner(website):
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


@app.route('/set_navbar_icon_url/<int:website_id>', methods=['POST'])
@login_required
@require_perm('appearance.navbar')
def set_navbar_icon_url(website_id):
    """Set the navbar icon to an arbitrary URL (or clear it) without touching
    any other navbar style settings."""
    website = Website.query.filter_by(
        id=website_id, user_id=current_user.root_user_id).first_or_404()
    data = request.get_json() or {}
    icon_url = (data.get('icon_url') or '').strip()
    from sqlalchemy.orm.attributes import flag_modified
    style = dict(website.public_navbar_style or {})
    if icon_url:
        style['icon_url'] = icon_url
    else:
        style.pop('icon_url', None)
    website.public_navbar_style = style
    flag_modified(website, 'public_navbar_style')
    db.session.commit()
    return jsonify({'success': True, 'icon_url': icon_url})


def update_music_section(section, form_data):
    def clean(value, fallback=''):
        return (value or fallback).strip()

    def safe_int(value, fallback, min_value=None, max_value=None):
        try:
            number = int(value or fallback)
        except (TypeError, ValueError):
            number = fallback

        if min_value is not None:
            number = max(min_value, number)

        if max_value is not None:
            number = min(max_value, number)

        return number

    section.content = {
        'title': clean(form_data.get('music_title'), 'Music'),
        'description': clean(form_data.get('music_description'), ''),
        'layout': clean(form_data.get('music_layout'), 'list'),
        'show_download': form_data.get('music_show_download') == 'on',
        'show_track_numbers': form_data.get('music_show_track_numbers') == 'on',
        'player_radius': safe_int(form_data.get('music_player_radius'), 18, 0, 40),
    }

    return section


def update_video_section(section, form_data):
    def clean(value, fallback=''):
        return (value or fallback).strip()

    def safe_int(value, fallback, min_value=None, max_value=None):
        try:
            number = int(value or fallback)
        except (TypeError, ValueError):
            number = fallback

        if min_value is not None:
            number = max(min_value, number)

        if max_value is not None:
            number = min(max_value, number)

        return number

    section.content = {
        'title': clean(form_data.get('video_title'), 'Videos'),
        'description': clean(form_data.get('video_description'), ''),
        'layout': clean(form_data.get('video_layout'), 'grid'),
        'show_download': form_data.get('video_show_download') == 'on',
        'show_filenames': form_data.get('video_show_filenames') == 'on',
        'corner_radius': safe_int(form_data.get('video_corner_radius'), 18, 0, 40),
        'max_width': safe_int(form_data.get('video_max_width'), 900, 240, 1600),
    }

    return section


def update_code_section(section, form_data):
    from sqlalchemy.orm.attributes import flag_modified
    incoming = form_data.get('code', '')
    existing_code = (section.content or {}).get('code', '')

    # Refuse to silently wipe code: if the incoming value is empty but saved
    # code is not, the textarea was never initialised (section never opened).
    # This prevents the bulk-save button from overwriting code with ''.
    if not incoming and existing_code:
        return section

    section.content = {**(section.content or {}), 'code': incoming}
    flag_modified(section, 'content')
    return section


def update_calendar_section(section, form_data):
    content = dict(section.content or {})
    allowed_style_keys = {
        'bg_color', 'text_color', 'header_bg', 'btn_bg', 'btn_text',
        'today_color', 'border_color', 'subscribe_bg', 'subscribe_text',
    }
    styles = {}
    for key in allowed_style_keys:
        val = (form_data.get(f'cal_style_{key}') or '').strip()
        if val:
            styles[key] = val
    content['styles'] = styles if styles else None
    section.content = content
    return section


def _touch_page(page_content_id):
    """Stamp last_edited_at / last_edited_by_id on the parent page without committing."""
    page = PublicPageContent.query.get(page_content_id)
    if page:
        page.last_edited_at = datetime.now(timezone.utc).replace(tzinfo=None)
        page.last_edited_by_id = current_user.id


@app.route('/update_section', methods=['POST'])
@login_required
@require_perm('sections.edit')
def update_section():
    section_id = request.form.get('section_id')
    section_type = request.form.get('section_type')

    # Debug logging to see what data is being received
    print(f"Received section_id: {section_id}, section_type: {section_type}")
    print(f"Form data: {request.form}")

    section = PageSection.query.get(section_id)
    if section is None:
        return jsonify({'status': 'error', 'message': 'Failed to update section'})

    # Version is tracked but not enforced here — the save flow has multiple
    # concurrent callers (bulk save button, auto-save) that would false-positive.

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
        section = update_contact_section(section, form_data)
    # elif section_type == 'header':
    #     section = update_header_section(section, form_data)
    elif section_type == 'youtube_video':
        section = update_youtube_video_section(section, form_data)
    elif section_type in ['video', 'videos']:
        section = update_video_section(section, form_data)
    # elif section_type == 'navbar':
    #     section = update_navbar_section(section, form_data)
    elif section_type == 'link_card':
        section = update_link_card_section(section, form_data)
    elif section_type == 'music':
        section = update_music_section(section, form_data)
    elif section_type == 'comments':
        section = update_comments_section(section, form_data)
    elif section_type == 'calendar':
        section = update_calendar_section(section, form_data)
    elif section_type == 'code':
        section = update_code_section(section, form_data)
    else:
        return jsonify({'status': 'error', 'message': 'Unknown section type'})

    section.version = (section.version or 0) + 1
    section.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    _touch_page(section.page_content_id)
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'{section_type} section updated',
                    'version': section.version})


@app.route('/toggle_public_page', methods=['POST'])
@login_required
def toggle_public_page():
    data = request.json
    site_active_status = data.get('site_active_status')
    website_id = data.get('website_id')
    page_id = data.get('page_id')  # Get the page_id from the request data
    print("Publish WEBSITE ID: ", website_id, " PAGE ID: ", page_id)

    # Verify the user owns the website
    website = Website.query.filter_by(id=website_id, user_id=current_user.root_user_id).first()

    if not website:
        return jsonify({'status': 'error', 'message': 'Unauthorized or invalid website ID'})

    # Update the site active status for the specific page
    content = PublicPageContent.query.filter_by(website_id=website_id, id=page_id).first()
    if content:
        if current_user.is_sub_admin:
            if not (current_user.has_permission('pages.publish')
                    or _folder_perm(content.page_folder_id, 'publish')):
                return jsonify({'status': 'error', 'message': 'Permission denied'}), 403
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


# @app.route('/update_image_order', methods=['POST'])
# @login_required
# def update_image_order_route():
#     # if not session.get('logged_in'):
#     #     return jsonify({'status': 'error', 'message': 'Unauthorized'})
#
#     # current_user is guaranteed to exist and be logged in
#     user_id = current_user.id  # or .get_id() depending on your User model
#
#     print(f"Logged in as user {user_id}")
#
#     order_list = request.json
#
#     if not isinstance(order_list, list) or not all(isinstance(order, dict) for order in order_list):
#         return jsonify({'status': 'error', 'message': 'Invalid request format'})
#
#     result = update_image_order(order_list)
#     return jsonify(result)


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


# @app.route('/move_image_to_section', methods=['POST'])
# @login_required
# def move_image_to_section():
#     data = request.json
#
#     if not data or 'sourceLinkId' not in data or 'sourceSection' not in data or 'targetSection' not in data:
#         return jsonify({'status': 'error', 'message': 'Invalid request format'})
#
#     source_link_id = data['sourceLinkId']
#     source_section_id = int(data['sourceSection'])
#     target_section_id = int(data['targetSection'])
#
#     try:
#         link = db.session.get(SectionImage, source_link_id)
#
#         if not link:
#             return jsonify({'status': 'error', 'message': 'SectionImage link not found'})
#
#         if link.section_id != source_section_id:
#             return jsonify({'status': 'error', 'message': 'Source section mismatch'})
#
#         # Move link to new section
#         link.section_id = target_section_id
#
#         db.session.flush()
#
#         # Re-number source section
#         source_links = SectionImage.query.filter_by(section_id=source_section_id).order_by(SectionImage.order).all()
#         for index, item in enumerate(source_links, start=1):
#             item.order = index
#
#         # Put moved image at end of target section
#         target_links = SectionImage.query.filter_by(section_id=target_section_id).order_by(SectionImage.order).all()
#         for index, item in enumerate(target_links, start=1):
#             item.order = index
#
#         db.session.commit()
#         return jsonify({'status': 'success', 'message': 'Image moved successfully'})
#
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'status': 'error', 'message': str(e)})


@app.route('/delete_section_image/<int:link_id>', methods=['DELETE'])
@login_required
def delete_section_image(link_id):
    try:
        section_asset = SectionAsset.query.get_or_404(link_id)
        section = PageSection.query.get_or_404(section_asset.section_id)

        if not user_owns_section(section):
            return jsonify({'success': False, 'error': 'Unauthorized.'}), 403

        db.session.delete(section_asset)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Image removed from section.'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/update_image_order', methods=['POST'])
@login_required
def update_image_order_route():
    order_list = request.get_json() or []

    if not isinstance(order_list, list):
        return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400

    try:
        for item in order_list:
            link_id = item.get('link_id')
            section_id = item.get('sectionId')
            new_order = item.get('order')

            link = SectionAsset.query.get(link_id)

            if not link:
                continue

            section = PageSection.query.get(link.section_id)

            if not section or not user_owns_section(section):
                continue

            # Allow moving order within target section too.
            if section_id:
                target_section = PageSection.query.get(section_id)

                if target_section and user_owns_section(target_section):
                    link.section_id = target_section.id

            link.order = int(new_order or 0)

        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Image order updated.'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/move_image_to_section', methods=['POST'])
@login_required
def move_image_to_section():
    data = request.get_json() or {}

    source_link_id = data.get('sourceLinkId')
    source_section_id = int(data.get('sourceSection'))
    target_section_id = int(data.get('targetSection'))

    try:
        link = SectionAsset.query.get_or_404(source_link_id)

        if link.section_id != source_section_id:
            return jsonify({'status': 'error', 'message': 'Source section mismatch'}), 400

        source_section = PageSection.query.get_or_404(source_section_id)
        target_section = PageSection.query.get_or_404(target_section_id)

        if not user_owns_section(source_section) or not user_owns_section(target_section):
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

        if target_section.section_type not in ['image', 'image_gallery', 'images']:
            return jsonify({'status': 'error', 'message': 'Target section does not accept images'}), 400

        max_order = db.session.query(func.coalesce(func.max(SectionAsset.order), 0)).filter_by(
            section_id=target_section.id
        ).scalar() or 0

        link.section_id = target_section.id
        link.order = max_order + 1

        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Image moved.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


# @app.route('/calendar/events/<int:section_id>.ics')
# def download_calendar_events(section_id):
#     # Fetch events from the database based on the provided section_id
#     events = CalendarEvent.query.filter_by(section_id=section_id).all()
#
#     # Check if events exist for the provided section_id
#     if not events:
#         return Response(status=404)
#
#     # Generate iCal feed for the specified section
#     cal = Calendar()
#     cal.add('prodid', '-//My Calendar//example.com//')
#     cal.add('version', '2.0')
#
#     for event in events:
#         event_obj = Event()
#         event_obj.add('summary', event.title)
#         event_obj.add('dtstart', event.start)
#         event_obj.add('dtend', event.end)
#         cal.add_component(event_obj)
#
#     # Return the iCal feed as a response
#     return Response(cal.to_ical(), mimetype='text/calendar')

def get_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For')

    if forwarded_for:
        return forwarded_for.split(',')[0].strip()

    return request.remote_addr or ''


def track_calendar_feed_subscriber(calendar_id):
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')

    raw_identity = f'cal:{calendar_id}|{ip_address}|{user_agent}'
    subscriber_hash = hashlib.sha256(raw_identity.encode('utf-8')).hexdigest()

    subscriber = CalendarFeedSubscriber.query.filter_by(
        calendar_id=calendar_id,
        subscriber_hash=subscriber_hash
    ).first()

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if subscriber:
        subscriber.last_seen_at = now
        subscriber.request_count += 1
    else:
        subscriber = CalendarFeedSubscriber(
            calendar_id=calendar_id,
            subscriber_hash=subscriber_hash,
            ip_address=ip_address,
            user_agent=user_agent,
            first_seen_at=now,
            last_seen_at=now,
            request_count=1
        )
        db.session.add(subscriber)

    db.session.commit()


def get_calendar_active_subscriber_count(calendar_id, days=30):
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)

    return CalendarFeedSubscriber.query.filter(
        CalendarFeedSubscriber.calendar_id == calendar_id,
        CalendarFeedSubscriber.last_seen_at >= cutoff
    ).count()


@app.route('/admin/calendar/<int:calendar_id>/subscriber_count')
@login_required
def calendar_subscriber_count(calendar_id):
    calendar = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(calendar.website_id)

    if not is_owner(website):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    active_7_days = get_calendar_active_subscriber_count(calendar_id, days=7)
    active_30_days = get_calendar_active_subscriber_count(calendar_id, days=30)
    total_seen = CalendarFeedSubscriber.query.filter_by(calendar_id=calendar_id).count()

    return jsonify({
        'success': True,
        'calendar_id': calendar_id,
        'active_7_days': active_7_days,
        'active_30_days': active_30_days,
        'total_seen': total_seen
    })


def get_calendar_subscriber_summary_for_websites(website_ids):
    if not website_ids:
        return {
            'active_7_days': 0,
            'active_30_days': 0,
            'total_seen': 0,
            'total_requests': 0,
            'top_calendars': []
        }

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff_7 = now - timedelta(days=7)
    cutoff_30 = now - timedelta(days=30)

    base_query = (
        db.session.query(CalendarFeedSubscriber)
        .join(Calendar, CalendarFeedSubscriber.calendar_id == Calendar.id)
        .filter(Calendar.website_id.in_(website_ids))
    )

    active_7_days = base_query.filter(
        CalendarFeedSubscriber.last_seen_at >= cutoff_7
    ).count()

    active_30_days = base_query.filter(
        CalendarFeedSubscriber.last_seen_at >= cutoff_30
    ).count()

    total_seen = base_query.count()

    total_requests = (
            db.session.query(func.coalesce(func.sum(CalendarFeedSubscriber.request_count), 0))
            .join(Calendar, CalendarFeedSubscriber.calendar_id == Calendar.id)
            .filter(Calendar.website_id.in_(website_ids))
            .scalar()
            or 0
    )

    top_rows = (
        db.session.query(
            Calendar.id.label('calendar_id'),
            Calendar.name.label('calendar_name'),
            func.count(CalendarFeedSubscriber.id).label('active_30_days'),
            func.coalesce(func.sum(CalendarFeedSubscriber.request_count), 0).label('requests')
        )
        .join(Calendar, CalendarFeedSubscriber.calendar_id == Calendar.id)
        .filter(
            Calendar.website_id.in_(website_ids),
            CalendarFeedSubscriber.last_seen_at >= cutoff_30
        )
        .group_by(Calendar.id, Calendar.name)
        .order_by(func.count(CalendarFeedSubscriber.id).desc())
        .limit(10)
        .all()
    )

    top_calendars = [
        {
            'calendar_id': row.calendar_id,
            'calendar_name': row.calendar_name,
            'active_30_days': row.active_30_days,
            'requests': row.requests
        }
        for row in top_rows
    ]

    return {
        'active_7_days': active_7_days,
        'active_30_days': active_30_days,
        'total_seen': total_seen,
        'total_requests': int(total_requests or 0),
        'top_calendars': top_calendars
    }


@app.route('/calendar/events/<int:section_id>.ics')
def calendar_events_feed(section_id):
    section = PageSection.query.get_or_404(section_id)

    if section.section_type != 'calendar':
        return Response('Not a calendar section', status=404)

    calendar_id = (section.content or {}).get('calendar_id') if section.content else None
    if not calendar_id:
        return Response('Calendar not configured', status=404)

    return _build_calendar_ical_response(calendar_id)


@app.route('/calendar/<int:calendar_id>.ics')
def calendar_feed_by_id(calendar_id):
    return _build_calendar_ical_response(calendar_id)


def _build_calendar_ical_response(calendar_id):
    cal_record = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(cal_record.website_id)

    track_calendar_feed_subscriber(calendar_id)

    events = (
        CalendarEvent.query
        .filter_by(calendar_id=calendar_id)
        .order_by(CalendarEvent.start)
        .all()
    )

    cal = ICalendar()
    cal.add('prodid', '-//Uwebia Calendar//uwebia//EN')
    cal.add('version', '2.0')
    cal.add('calscale', 'GREGORIAN')
    cal.add('method', 'PUBLISH')

    cal.add('X-WR-CALNAME', cal_record.name)
    cal.add('X-WR-CALDESC', cal_record.description or cal_record.name)
    cal.add('X-WR-TIMEZONE', 'America/Chicago')
    cal.add('REFRESH-INTERVAL;VALUE=DURATION', 'PT15M')
    cal.add('X-PUBLISHED-TTL', 'PT15M')

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for event in events:
        event_obj = ICalEvent()
        event_obj.add('uid', f'uwebia-event-{event.id}@{request.host}')
        event_obj.add('summary', event.title or 'Untitled Event')

        if event.description:
            event_obj.add('description', event.description)

        event_obj.add('dtstamp', now)
        event_obj.add('last-modified', now)
        event_obj.add('dtstart', event.start)

        if event.end:
            event_obj.add('dtend', event.end)
        else:
            event_obj.add('dtend', event.start + timedelta(hours=1))

        cal.add_component(event_obj)

    response = make_response(cal.to_ical())
    response.headers['Content-Type'] = 'text/calendar; charset=utf-8'
    response.headers['Content-Disposition'] = f'inline; filename="uwebia-calendar-{calendar_id}.ics"'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


def _parse_event_datetime(dt_str, timezone):
    if not dt_str:
        return None
    dt = parser.parse(str(dt_str))
    if dt.tzinfo is None:
        return timezone.localize(dt)
    return dt.astimezone(timezone)


def _fetch_and_parse_ical(url):
    url = url.strip().replace('webcal://', 'https://')
    import requests as req_lib
    resp = req_lib.get(url, timeout=12, headers={'User-Agent': 'Uwebia/1.0'})
    resp.raise_for_status()
    return ICalendar.from_ical(resp.content)


def sync_subscription(sub):
    """Fetch one external iCal subscription and replace its events."""
    from datetime import date as date_type

    try:
        cal_data = _fetch_and_parse_ical(sub.url)
    except Exception as e:
        sub.last_sync_error = str(e)
        db.session.commit()
        return {'synced': 0, 'error': str(e)}

    local_tz = pytz.timezone('America/Chicago')

    try:
        CalendarEvent.query.filter_by(subscription_id=sub.id).delete()

        count = 0
        for component in cal_data.walk():
            if component.name != 'VEVENT':
                continue
            dtstart = component.get('dtstart')
            if not dtstart:
                continue

            start = dtstart.dt
            dtend = component.get('dtend')
            end = dtend.dt if dtend else None

            if isinstance(start, date_type) and not isinstance(start, datetime):
                start = local_tz.localize(datetime.combine(start, datetime.min.time()))
            elif start.tzinfo is None:
                start = local_tz.localize(start)
            else:
                start = start.astimezone(local_tz)

            if end is not None:
                if isinstance(end, date_type) and not isinstance(end, datetime):
                    end = local_tz.localize(datetime.combine(end, datetime.min.time()))
                elif end.tzinfo is None:
                    end = local_tz.localize(end)
                else:
                    end = end.astimezone(local_tz)

            db.session.add(CalendarEvent(
                title=str(component.get('summary', 'Untitled')),
                description=str(component.get('description', '')) or None,
                start=start,
                end=end,
                calendar_id=sub.calendar_id,
                source='external',
                subscription_id=sub.id,
            ))
            count += 1

        sub.last_synced_at = datetime.now(timezone.utc).replace(tzinfo=None)
        sub.last_sync_error = None
        sub.event_count = count
        db.session.commit()
        return {'synced': count, 'error': None}

    except Exception as e:
        db.session.rollback()
        return {'synced': 0, 'error': str(e)}


def sync_all_stale_subscriptions(calendar):
    """Sync all subscriptions for a calendar that are stale (>15 min old)."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for sub in calendar.subscriptions:
        stale = (
                sub.last_synced_at is None or
                (now - sub.last_synced_at).total_seconds() > 900
        )
        if stale:
            sync_subscription(sub)


_sync_scheduler_started = False


def _start_subscription_sync_scheduler():
    """Start a background daemon thread that syncs all stale external calendar
    subscriptions every 15 minutes, independent of web traffic."""
    import threading
    import time

    global _sync_scheduler_started
    if _sync_scheduler_started:
        return
    _sync_scheduler_started = True

    def _loop():
        # Short initial delay so the server finishes starting before the first sync.
        time.sleep(60)
        while True:
            try:
                with app.app_context():
                    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15)
                    stale = CalendarSubscription.query.filter(
                        or_(
                            CalendarSubscription.last_synced_at == None,
                            CalendarSubscription.last_synced_at < cutoff
                        )
                    ).all()
                    for sub in stale:
                        try:
                            sync_subscription(sub)
                        except Exception as sub_err:
                            print(f"[calendar sync] subscription {sub.id} error: {sub_err}")
            except Exception as loop_err:
                print(f"[calendar sync] scheduler error: {loop_err}")
            time.sleep(900)  # 15 minutes

    t = threading.Thread(target=_loop, daemon=True, name='calendar-sub-sync')
    t.start()
    print("[calendar sync] background sync scheduler started (interval: 15 min)")


@app.route('/calendar/<int:calendar_id>/events', methods=['GET'])
def get_calendar_events_public(calendar_id):
    cal = Calendar.query.get_or_404(calendar_id)
    if cal.subscriptions:
        sync_all_stale_subscriptions(cal)
    events = CalendarEvent.query.filter_by(calendar_id=calendar_id).all()
    return jsonify([event.to_dict() for event in events])


@app.route('/admin/calendars/<int:calendar_id>/subscriptions', methods=['POST'])
@login_required
@require_perm('calendars.subscriptions')
def add_calendar_subscription(calendar_id):
    cal = Calendar.query.get_or_404(calendar_id)
    if Website.query.get_or_404(cal.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'}), 400

    sub = CalendarSubscription(
        calendar_id=calendar_id,
        name=(data.get('name') or '').strip() or None,
        url=url,
    )
    db.session.add(sub)
    db.session.commit()

    result = sync_subscription(sub)
    return jsonify({'success': True, 'subscription': sub.to_dict(), 'sync': result}), 201


@app.route('/admin/calendars/<int:calendar_id>/subscriptions/<int:sub_id>/sync', methods=['POST'])
@login_required
def sync_one_subscription(calendar_id, sub_id):
    sub = CalendarSubscription.query.filter_by(id=sub_id, calendar_id=calendar_id).first_or_404()
    if Website.query.get_or_404(sub.calendar.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    result = sync_subscription(sub)
    if result['error']:
        return jsonify({'success': False, 'error': result['error'], 'subscription': sub.to_dict()}), 400
    return jsonify({'success': True, 'synced': result['synced'], 'subscription': sub.to_dict()})


@app.route('/admin/calendars/<int:calendar_id>/subscriptions/<int:sub_id>/delete', methods=['POST'])
@login_required
@require_perm('calendars.subscriptions')
def delete_calendar_subscription(calendar_id, sub_id):
    sub = CalendarSubscription.query.filter_by(id=sub_id, calendar_id=calendar_id).first_or_404()
    if Website.query.get_or_404(sub.calendar.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    CalendarEvent.query.filter_by(subscription_id=sub_id).delete()
    db.session.delete(sub)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/calendars/<int:calendar_id>/sync', methods=['POST'])
@login_required
def sync_calendar_now(calendar_id):
    cal = Calendar.query.get_or_404(calendar_id)
    if Website.query.get_or_404(cal.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    results = []
    for sub in cal.subscriptions:
        r = sync_subscription(sub)
        results.append({'subscription_id': sub.id, 'name': sub.name or sub.url, **r})
    return jsonify({'success': True, 'results': results})


def _parse_calendar_styles(raw):
    if not raw or not isinstance(raw, dict):
        return None
    allowed = set(CALENDAR_STYLE_DEFAULTS.keys())
    return {k: v for k, v in raw.items() if k in allowed and isinstance(v, str) and v.strip()}


@app.route('/admin/calendars/list', methods=['GET'])
@login_required
def list_calendars():
    website = get_admin_website()
    if not website:
        return jsonify({'calendars': []})
    calendars = Calendar.query.filter_by(website_id=website.id).order_by(Calendar.created_at.desc()).all()
    return jsonify({'calendars': [c.to_dict() for c in calendars]})


@app.route('/admin/ai-agents')
@login_required
def ai_agents_page():
    website = get_admin_website()
    agents = AIAgent.query.filter_by(website_id=website.id).order_by(AIAgent.created_at).all() if website else []
    current_website = website
    current_website_pages = PublicPageContent.query.filter_by(website_id=website.id).order_by(
        PublicPageContent.sort_order, PublicPageContent.id
    ).all() if website else []
    return render_template('ai_agents.html', agents=agents,
                           current_website=current_website,
                           current_website_pages=current_website_pages,
                           page_id=None)


# ── Admin Users ───────────────────────────────────────────────────────────────

ADMIN_PERMISSIONS = {
    'website': {'label': 'Website', 'actions': {
        'edit': 'Edit website name, description & tags',
        'draft.create': 'Create a draft copy of the live website',
        'draft.edit': 'Edit sections & content inside the draft website',
        'draft.pages': 'Add, delete & manage pages inside the draft website',
        'draft.promote': 'Promote draft to live (replaces live site)',
    }},
    'pages': {'label': 'Pages', 'actions': {
        'view': 'View pages list',
        'edit': 'Open page editor',
        'details': 'Edit page name, description & tags',
        'create': 'Create new pages inside folders',
        'create_root': 'Create pages at the root level (outside any folder)',
        'create_folder': 'Create new page folders',
        'delete': 'Delete pages',
        'delete_folder': 'Delete page folders',
        'publish': 'Publish / unpublish pages',
        'reorder': 'Drag to reorder pages and move them into/out of folders',
        'templates': 'Save & apply page templates',
    }},
    'sections': {'label': 'Sections & Groups', 'actions': {
        'edit': 'Edit section content',
        'create': 'Add new sections',
        'delete': 'Delete sections',
        'reorder': 'Drag & reorder sections / rows',
        'groups': 'Create, style & manage section groups',
        'templates': 'Save & apply section templates',
    }},
    'appearance': {'label': 'Appearance', 'actions': {
        'background': 'Change background color / image',
        'navbar': 'Edit navbar links & style',
        'colors': 'Use saved color palette',
        'page_code': 'Use page-level code editor',
    }},
    'code': {'label': 'Code', 'actions': {
        'sections': 'Edit code sections (full HTML/CSS/JS)',
        'tweaks': 'Use per-section code tweaks',
        'ai': 'Use AI to generate / modify code',
    }},
    'assets': {'label': 'Asset Library', 'actions': {
        'view': 'View assets',
        'upload': 'Upload files',
        'delete': 'Delete assets',
        'folders': 'Create & manage folders',
        'ai_generate': 'Generate images with AI',
        'download': 'Download original files',
    }},
    'calendars': {'label': 'Calendars', 'actions': {
        'view': 'View calendars',
        'create': 'Create calendars',
        'edit': 'Edit calendars & subscriptions',
        'delete': 'Delete calendars',
        'events': 'Create, edit & delete events',
        'subscriptions': 'Manage external calendar feeds',
    }},
    'forum': {'label': 'Forum', 'actions': {
        'view': 'View forum admin page',
        'settings': 'Edit forum settings',
        'moderate': 'Approve & reject threads / replies',
        'delete_posts': 'Delete threads & replies',
        'manage_users': 'Moderate forum users (ban, verify, etc.)',
    }},
    'comments': {'label': 'Page Comments', 'actions': {
        'view': 'View page comments',
        'moderate': 'Approve & reject comments',
        'delete': 'Delete comments',
    }},
    'messages': {'label': 'Contact Messages', 'actions': {
        'view': 'View contact form messages',
        'delete': 'Delete messages',
    }},
    'ai_agents': {'label': 'AI Agents', 'actions': {
        'view': 'View agents',
        'create': 'Create agents',
        'edit': 'Edit agents & API keys',
        'delete': 'Delete agents',
        'chat': 'Chat with agents',
        'use': 'Use agents for code & image generation',
    }},
    'analytics': {'label': 'Analytics', 'actions': {
        'view': 'View analytics dashboard & visitor stats',
        'export': 'Export analytics data',
        'geoip': 'Upload, delete & configure GeoIP location databases',
    }},
    'settings': {'label': 'Site Settings', 'actions': {
        'view': 'View site settings',
        'edit': 'Edit general settings',
        'email': 'Edit email server settings',
        '2fa': 'Manage two-factor authentication',
    }},
    'templates': {'label': 'Templates', 'actions': {
        'view': 'View saved templates',
        'create': 'Save new templates',
        'delete': 'Delete templates',
    }},
    'admin_users': {'label': 'Admin Users', 'actions': {
        'view': 'View admin users',
        'create': 'Create admin users',
        'edit': 'Edit admin users & permissions',
        'delete': 'Delete admin users',
    }},
}


@app.route('/admin/users')
@login_required
def admin_users_page():
    if current_user.is_sub_admin:
        if not current_user.has_permission('admin_users.view'):
            return jsonify({'error': 'Permission denied'}), 403
    sub_admins = User.query.filter_by(parent_user_id=current_user.root_user_id).all()
    website = get_admin_website()
    # Pass all pages, sections, and folders so the main admin can assign access
    all_pages = PublicPageContent.query.filter_by(website_id=website.id).order_by(
        PublicPageContent.sort_order, PublicPageContent.name).all() if website else []
    all_sections = []
    for page in all_pages:
        for s in PageSection.query.filter_by(page_content_id=page.id).all():
            if s.column and s.column.row:
                all_sections.append({
                    'id': s.id,
                    'page_id': page.id,
                    'page_name': page.name,
                    'label': s.label or s.section_type,
                    'type': s.section_type,
                })
    root_user_id = current_user.root_user_id
    all_folders = AssetFolder.query.filter_by(user_id=root_user_id).order_by(AssetFolder.name).all()
    all_page_folders = PageFolder.query.filter_by(website_id=website.id).order_by(
        PageFolder.sort_order, PageFolder.id).all() if website else []
    # Build section groups with their page name and section list
    all_groups_raw = SectionGroup.query.filter(
        SectionGroup.page_content_id.in_([p.id for p in all_pages])
    ).order_by(SectionGroup.group_order).all() if all_pages else []
    page_name_map = {p.id: p.name for p in all_pages}
    all_groups = []
    for g in all_groups_raw:
        # Collect section IDs that belong to this group via rows
        group_rows = Row.query.filter_by(section_group_id=g.id).all()
        section_ids = []
        for row in group_rows:
            for col in row.columns:
                if col.section_id:
                    section_ids.append(col.section_id)
        all_groups.append({
            'id': g.id,
            'name': g.name or 'Section Group',
            'page_id': g.page_content_id,
            'page_name': page_name_map.get(g.page_content_id, ''),
            'section_ids': section_ids,
        })
    perm_groups = PermissionGroup.query.filter_by(owner_user_id=current_user.root_user_id).order_by(
        PermissionGroup.name).all()
    return render_template('admin_users.html',
                           sub_admins=sub_admins,
                           permissions_schema=ADMIN_PERMISSIONS,
                           all_pages=[{'id': p.id, 'name': p.name, 'slug': p.slug} for p in all_pages],
                           all_sections=all_sections,
                           all_folders=[{'id': f.id, 'name': f.name, 'asset_type': f.asset_type} for f in all_folders],
                           all_page_folders=[{'id': f.id, 'name': f.name} for f in all_page_folders],
                           all_groups=all_groups,
                           permission_groups=perm_groups,
                           current_website=website,
                           now=datetime.now(timezone.utc).replace(tzinfo=None),
                           page_id=None)


@app.route('/admin/users/create', methods=['POST'])
@login_required
def create_admin_user():
    if current_user.is_sub_admin and not current_user.has_permission('admin_users.create'):
        return _utf8_json({'success': False, 'error': 'Permission denied'}, 403)
    data = request.get_json() or {}
    username = (data.get('username') or '').strip().lower()
    email = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    perms = data.get('permissions') or {}
    group_id = data.get('permission_group_id') or None
    if not username or not email or not password:
        return _utf8_json({'success': False, 'error': 'Username, email and password are required'}, 400)
    if len(password) < 8:
        return _utf8_json({'success': False, 'error': 'Password must be at least 8 characters'}, 400)
    if User.query.filter_by(username=username).first():
        return _utf8_json({'success': False, 'error': 'Username already taken'}, 400)
    if User.query.filter_by(email=email).first():
        return _utf8_json({'success': False, 'error': 'Email already in use'}, 400)
    if group_id:
        grp = PermissionGroup.query.get(group_id)
        if not grp or grp.owner_user_id != current_user.root_user_id:
            group_id = None
    sub = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        parent_user_id=current_user.root_user_id,
        permission_group_id=group_id,
        permissions=perms if not group_id else {},
        _is_active=True,
    )
    db.session.add(sub)
    db.session.commit()
    return _utf8_json({'success': True, 'user': {'id': sub.id, 'username': sub.username, 'email': sub.email}}, 201)


@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@login_required
def update_admin_user(user_id):
    if current_user.is_sub_admin and not current_user.has_permission('admin_users.edit'):
        return _utf8_json({'success': False, 'error': 'Permission denied'}, 403)
    sub = User.query.get_or_404(user_id)
    if sub.parent_user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = (data.get('password') or '').strip()
    perms = data.get('permissions')
    active = data.get('active')
    group_id_raw = data.get('permission_group_id', '__unset__')
    if email and email != sub.email:
        if User.query.filter(User.email == email, User.id != sub.id).first():
            return _utf8_json({'success': False, 'error': 'Email already in use'}, 400)
        sub.email = email
    if password:
        if len(password) < 8:
            return _utf8_json({'success': False, 'error': 'Password must be at least 8 characters'}, 400)
        sub.password_hash = generate_password_hash(password)
    if group_id_raw != '__unset__':
        group_id = group_id_raw or None
        if group_id:
            grp = PermissionGroup.query.get(group_id)
            if not grp or grp.owner_user_id != current_user.root_user_id:
                group_id = None
        sub.permission_group_id = group_id
        if group_id:
            sub.permissions = {}
        elif perms is not None:
            sub.permissions = perms
    elif perms is not None:
        sub.permissions = perms
    if active is not None:
        sub._is_active = bool(active)
    db.session.commit()
    return _utf8_json({'success': True})


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_admin_user(user_id):
    if current_user.is_sub_admin and not current_user.has_permission('admin_users.delete'):
        return _utf8_json({'success': False, 'error': 'Permission denied'}, 403)
    sub = User.query.get_or_404(user_id)
    if sub.parent_user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    db.session.delete(sub)
    db.session.commit()
    return _utf8_json({'success': True})


# ── Permission Groups ─────────────────────────────────────────────────────────

@app.route('/admin/permission-groups', methods=['GET'])
@login_required
def list_permission_groups():
    if current_user.is_sub_admin:
        return _utf8_json({'error': 'Permission denied'}, 403)
    groups = PermissionGroup.query.filter_by(owner_user_id=current_user.id).order_by(PermissionGroup.name).all()
    return _utf8_json({'groups': [g.to_dict() for g in groups]})


@app.route('/admin/permission-groups/create', methods=['POST'])
@login_required
def create_permission_group():
    if current_user.is_sub_admin:
        return _utf8_json({'error': 'Permission denied'}, 403)
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return _utf8_json({'success': False, 'error': 'Name is required'}, 400)
    grp = PermissionGroup(
        owner_user_id=current_user.id,
        name=name,
        description=(data.get('description') or '').strip() or None,
        permissions=data.get('permissions') or {},
    )
    db.session.add(grp)
    db.session.commit()
    return _utf8_json({'success': True, 'group': grp.to_dict()}, 201)


@app.route('/admin/permission-groups/<int:group_id>/update', methods=['POST'])
@login_required
def update_permission_group(group_id):
    if current_user.is_sub_admin:
        return _utf8_json({'error': 'Permission denied'}, 403)
    grp = PermissionGroup.query.get_or_404(group_id)
    if grp.owner_user_id != current_user.id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if name:
        grp.name = name
    if 'description' in data:
        grp.description = (data['description'] or '').strip() or None
    if 'permissions' in data:
        grp.permissions = data['permissions'] or {}
    db.session.commit()
    return _utf8_json({'success': True, 'group': grp.to_dict()})


@app.route('/admin/permission-groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_permission_group(group_id):
    if current_user.is_sub_admin:
        return _utf8_json({'error': 'Permission denied'}, 403)
    grp = PermissionGroup.query.get_or_404(group_id)
    if grp.owner_user_id != current_user.id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    # Unlink members before deleting the group
    User.query.filter_by(permission_group_id=grp.id).update({'permission_group_id': None}, synchronize_session=False)
    db.session.delete(grp)
    db.session.commit()
    return _utf8_json({'success': True})


@app.route('/admin/ai-agents/list')
@login_required
def list_ai_agents():
    website = get_admin_website()
    if not website:
        return jsonify({'agents': []})
    agents = AIAgent.query.filter_by(website_id=website.id).order_by(AIAgent.created_at).all()
    return jsonify({'agents': [a.to_dict() for a in agents]})


@app.route('/admin/ai-agents/create', methods=['POST'])
@login_required
@require_perm('ai_agents.create')
def create_ai_agent():
    website = get_admin_website()
    if not website:
        return jsonify({'success': False, 'error': 'No website found'}), 400
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400
    raw_key = (data.get('api_key') or '').strip()
    caps = (data.get('capabilities') or 'chat').strip()
    if caps not in ('chat', 'image', 'both'):
        caps = 'chat'
    agent = AIAgent(
        website_id=website.id,
        name=name,
        provider=(data.get('provider') or 'openai_compatible').strip(),
        api_url=(data.get('api_url') or '').strip() or None,
        api_key=encrypt_api_key(raw_key) if raw_key else None,
        model=(data.get('model') or '').strip() or None,
        system_prompt=(data.get('system_prompt') or '').strip() or None,
        capabilities=caps,
    )
    db.session.add(agent)
    db.session.commit()
    return jsonify({'success': True, 'agent': agent.to_dict()}), 201


@app.route('/admin/ai-agents/<int:agent_id>/update', methods=['POST'])
@login_required
@require_perm('ai_agents.edit')
def update_ai_agent(agent_id):
    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400
    agent.name = name
    agent.provider = (data.get('provider') or 'openai_compatible').strip()
    agent.api_url = (data.get('api_url') or '').strip() or None
    agent.model = (data.get('model') or '').strip() or None
    agent.system_prompt = (data.get('system_prompt') or '').strip() or None
    new_caps = (data.get('capabilities') or 'chat').strip()
    agent.capabilities = new_caps if new_caps in ('chat', 'image', 'both') else 'chat'
    new_key = (data.get('api_key') or '').strip()
    if new_key and not all(c == '*' for c in new_key):
        agent.api_key = encrypt_api_key(new_key)
    db.session.commit()
    return jsonify({'success': True, 'agent': agent.to_dict()})


@app.route('/admin/ai-agents/<int:agent_id>/delete', methods=['POST'])
@login_required
@require_perm('ai_agents.delete')
def delete_ai_agent(agent_id):
    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    db.session.delete(agent)
    db.session.commit()
    return jsonify({'success': True})


def _scope_section_css(html: str, section_id: int) -> str:
    """
    Find every <style> block in html and prefix all CSS selectors with
    #section-{section_id} so they only affect that section.
    At-rules (@keyframes, @font-face, @import) are left untouched.
    @media/@supports blocks have their inner rules scoped.
    """
    import re

    prefix = f'#section-{section_id}'

    def scope_rule(selector_text: str) -> str:
        """Add prefix to each comma-separated selector, skipping at-rules and :root/html/body."""
        stripped = selector_text.strip()
        if not stripped or stripped.startswith('@'):
            return selector_text
        parts = []
        for sel in stripped.split(','):
            sel = sel.strip()
            if not sel:
                continue
            # Don't double-scope, and don't touch :root / html / body rules
            if sel.startswith(prefix) or sel.lower() in (':root', 'html', 'body'):
                parts.append(sel)
            else:
                parts.append(f'{prefix} {sel}')
        return ', '.join(parts)

    def scope_css_block(css: str) -> str:
        """Scope all rules in a CSS text block."""
        result = []
        i = 0
        while i < len(css):
            # Find next { or end
            brace = css.find('{', i)
            if brace == -1:
                result.append(css[i:])
                break
            selector_part = css[i:brace]
            stripped = selector_part.strip()
            # At-rule with nested block (@media, @supports, @keyframes, @layer)
            if stripped.startswith('@'):
                close = _find_matching_brace(css, brace)
                inner = css[brace + 1:close]
                at_keyword = stripped.split('(')[0].strip().lower()
                # @keyframes and @font-face: don't scope inner rules
                if any(at_keyword.startswith(k) for k in ('@keyframes', '@-webkit-keyframes', '@font-face')):
                    result.append(selector_part + '{' + inner + '}')
                else:
                    result.append(selector_part + '{' + scope_css_block(inner) + '}')
                i = close + 1
            else:
                close = css.find('}', brace)
                if close == -1:
                    result.append(scope_rule(selector_part) + '{' + css[brace + 1:])
                    break
                declarations = css[brace + 1:close]
                result.append(scope_rule(selector_part) + '{' + declarations + '}')
                i = close + 1
        return ''.join(result)

    def _find_matching_brace(s: str, open_pos: int) -> int:
        depth = 0
        for idx in range(open_pos, len(s)):
            if s[idx] == '{':
                depth += 1
            elif s[idx] == '}':
                depth -= 1
                if depth == 0:
                    return idx
        return len(s) - 1

    def replace_style_block(m):
        attrs = m.group(1) or ''
        css = m.group(2)
        return f'<style{attrs}>{scope_css_block(css)}</style>'

    return re.sub(r'<style([^>]*)>([\s\S]*?)</style>', replace_style_block, html,
                  flags=re.IGNORECASE)


def _strip_code_fences(text):
    """Extract raw HTML from AI responses that may wrap code in markdown fences or prose."""
    import re
    text = text.strip()

    # If the response contains a fenced code block, extract just the block's content.
    # Handles ``` with or without a language tag, and multiple fences.
    fenced = re.search(r'```[a-zA-Z]*\n([\s\S]*?)```', text)
    if fenced:
        return fenced.group(1).strip()

    # If there's no fence but the model prepended a short prose line before the HTML
    # (e.g. "Here is the updated code:\n\n<div>..."), strip everything before the
    # first HTML tag.
    html_start = re.search(r'<[a-zA-Z]', text)
    if html_start and html_start.start() > 0:
        return text[html_start.start():].strip()

    return text


@app.route('/section/<int:section_id>/save_code', methods=['POST'])
@login_required
@require_perm('code.sections')
def save_code_section(section_id):
    try:
        section = PageSection.query.get_or_404(section_id)
        page = PublicPageContent.query.get_or_404(section.page_content_id)
        website = Website.query.get_or_404(page.website_id)
        if not is_owner(website):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        data = request.get_json(force=True, silent=True) or {}
        code = data.get('code', '')
        agent_id = data.get('agent_id')
        client_version = data.get('version')

        # Full assignment + flag_modified ensures SQLAlchemy detects the JSON change
        from sqlalchemy.orm.attributes import flag_modified
        section.content = {'code': code, 'agent_id': agent_id}
        flag_modified(section, 'content')
        section.version = (section.version or 0) + 1
        section.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        _touch_page(section.page_content_id)
        db.session.commit()

        app.logger.info(f'save_code_section {section_id}: saved {len(code)} chars, agent={agent_id}')
        return jsonify({'success': True, 'version': section.version})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'save_code_section {section_id} error: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/section_templates/grouped', methods=['GET'])
@login_required
def section_templates_grouped():
    website = get_admin_website()
    if not website:
        return jsonify({'grouped': {}})
    templates = SectionTemplate.query.filter_by(website_id=website.id).order_by(
        SectionTemplate.section_type, SectionTemplate.name).all()
    grouped = {}
    for t in templates:
        grouped.setdefault(t.section_type, []).append(
            {'id': t.id, 'name': t.name, 'section_type': t.section_type})
    return jsonify({'grouped': grouped})


@app.route('/admin/section/<int:section_id>/save_as_template', methods=['POST'])
@login_required
@require_perm('sections.templates')
def save_section_as_template(section_id):
    section = PageSection.query.get_or_404(section_id)
    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    name = (data.get('name') or section.label or section.section_type).strip()
    tmpl = SectionTemplate(
        website_id=website.id,
        name=name,
        section_type=section.section_type,
        content=section.content,
        custom_code=section.custom_code,
    )
    db.session.add(tmpl)
    db.session.commit()
    return jsonify({'success': True, 'template': tmpl.to_dict()}), 201


@app.route('/admin/section_templates/<int:template_id>/rename', methods=['POST'])
@login_required
@require_perm('sections.templates')
def rename_section_template(template_id):
    tmpl = SectionTemplate.query.get_or_404(template_id)
    if Website.query.get_or_404(tmpl.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Name cannot be empty'}), 400
    tmpl.name = name
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/section_templates/<int:template_id>/delete', methods=['POST'])
@login_required
@require_perm('sections.templates')
def delete_section_template(template_id):
    tmpl = SectionTemplate.query.get_or_404(template_id)
    if Website.query.get_or_404(tmpl.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    db.session.delete(tmpl)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/section_template/<int:template_id>/apply', methods=['POST'])
@login_required
@require_perm('sections.templates')
def apply_section_template(template_id):
    tmpl = SectionTemplate.query.get_or_404(template_id)
    website = Website.query.get_or_404(tmpl.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    page_id = data.get('page_id')
    row_id = data.get('row_id')
    column_id = data.get('column_id')
    page = PublicPageContent.query.get_or_404(page_id)
    if Website.query.get_or_404(page.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    column = Column.query.get_or_404(column_id)
    section = PageSection(
        section_type=tmpl.section_type,
        order=1,
        content=tmpl.content,
        custom_code=tmpl.custom_code,
        label=tmpl.name,
        page_content_id=page.id,
        column=column,
    )
    db.session.add(section)
    db.session.commit()
    return jsonify({'success': True, 'section_id': section.id})


@app.route('/section/<int:section_id>/save_label', methods=['POST'])
@login_required
@require_perm('sections.edit')
def save_section_label(section_id):
    section = PageSection.query.get_or_404(section_id)
    page = PublicPageContent.query.get_or_404(section.page_content_id)
    if Website.query.get_or_404(page.website_id).user_id != current_user.root_user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.get_json(force=True, silent=True) or {}
    section.label = (data.get('label') or '').strip() or None
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/section/<int:section_id>/rendered_html')
@login_required
def section_rendered_html(section_id):
    from bs4 import BeautifulSoup
    section = PageSection.query.get_or_404(section_id)
    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    try:
        response = render_public_page(website, page, is_preview=True)
        full_html = response.get_data(as_text=True)
        soup = BeautifulSoup(full_html, 'html.parser')
        el = soup.find(id=f'section-{section_id}')
        snippet = el.decode_contents().strip() if el else '(section not found in rendered page)'
    except Exception as e:
        snippet = f'(render error: {e})'
    return _utf8_json({'success': True, 'html': snippet})


@app.route('/admin/section/<int:section_id>/ai_assist_tweaks', methods=['POST'])
@login_required
@require_perm('code.ai')
def ai_assist_section_tweaks(section_id):
    from bs4 import BeautifulSoup
    section = PageSection.query.get_or_404(section_id)
    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    data = request.get_json() or {}
    agent_id = data.get('agent_id')
    prompt = (data.get('prompt') or '').strip()
    current_code = (data.get('current_code') or '').strip()

    if not agent_id:
        return _utf8_json({'success': False, 'error': 'No agent selected'}, 400)
    if not prompt:
        return _utf8_json({'success': False, 'error': 'Prompt is required'}, 400)

    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    # Get the section's rendered HTML
    try:
        response = render_public_page(website, page, is_preview=True)
        full_html = response.get_data(as_text=True)
        soup = BeautifulSoup(full_html, 'html.parser')
        el = soup.find(id=f'section-{section_id}')
        section_html = el.decode_contents().strip() if el else '(section HTML not found)'
    except Exception as e:
        section_html = f'(render error: {e})'

    if current_code:
        existing_block = (
            f'EXISTING TWEAKS CODE — include every line verbatim in your output with changes integrated:\n'
            f'{current_code}'
        )
    else:
        existing_block = 'EXISTING TWEAKS CODE: (empty — write from scratch)'

    section_type = section.section_type

    # Provide section-type-specific class hints so the AI targets the right elements
    type_hints = {
        'button': "The button is an <a> tag with class 'section-button' inside a div.section-button-wrap.",
        'text': "Text content is inside a div.text-area.",
        'images': "Images use class 'uwebia-images' as the container.",
        'music': "Music uses class 'uwebia-music'.",
        'video': "Video uses class 'uwebia-video-section'.",
        'calendar': "Calendar uses class 'calendar'.",
        'link_card': "Link card uses class 'uwebia-link-card'.",
        'contact_form': "Form uses class 'contact-form-container'.",
    }
    type_hint = type_hints.get(section_type, '')

    system_override = (
            "You are a CSS/JS assistant embedded in Uwebia, a website builder.\n"
            f"The user is writing targeted tweaks for a '{section_type}' section with DOM id 'section-{section_id}'.\n"
            + (f"Section structure note: {type_hint}\n" if type_hint else '')
            + "This code is injected immediately after the section — it must ONLY affect that section.\n\n"
              "Scoping rules (critical):\n"
              f"- ALL CSS selectors must be prefixed with '#section-{section_id}'.\n"
              f"  Example: '#section-{section_id} .section-button {{ background: blue; }}'\n"
              "- ALL JavaScript must be inside an IIFE: (function(){{ ... }})();\n"
              "  Use const/let and arrow functions only — no 'function foo()' declarations (they leak to global scope).\n"
              f"- Target elements with: document.querySelector('#section-{section_id} .class-name')\n"
              "  Never use getElementById with a hardcoded id — ids must be unique per page.\n\n"
              "Other rules:\n"
              "- Return ONLY raw HTML/CSS/JS. No explanations, no markdown, no code fences.\n"
              "- You MAY use <style> and <script> blocks. Do NOT include <html>, <head>, or <body> tags.\n"
              "- OUTPUT RULE: Include every line of the existing code verbatim and integrate your changes. "
              "Never summarise or replace existing code with placeholder comments."
    )

    user_message = (
        f"Section inner HTML (the elements you are styling):\n\n{section_html}\n\n"
        f"---\n\n{existing_block}\n\n"
        f"---\n\nMODIFICATION REQUEST: {prompt}"
    )

    original_system = agent.system_prompt
    agent.system_prompt = system_override
    reply, error = _call_ai_agent(agent, [{'role': 'user', 'content': user_message}])
    agent.system_prompt = original_system

    if error:
        return _utf8_json({'success': False, 'error': error}, 502)
    return _utf8_json({'success': True, 'code': _strip_code_fences(reply)})


@app.route('/section/<int:section_id>/save_tweaks', methods=['POST'])
@login_required
@require_perm('sections.edit')
def save_section_tweaks(section_id):
    try:
        section = PageSection.query.get_or_404(section_id)
        page = PublicPageContent.query.get_or_404(section.page_content_id)
        if Website.query.get_or_404(page.website_id).user_id != current_user.root_user_id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        data = request.get_json(force=True, silent=True) or {}
        section.custom_code = data.get('code') or None
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


def _build_asset_inventory(user_id):
    """Return a folder-aware asset inventory string for AI prompts."""
    folders = {f.id: f.name for f in AssetFolder.query.filter_by(user_id=user_id).all()}
    assets = Asset.query.filter_by(user_id=user_id).order_by(Asset.upload_date.desc()).all()

    # Group by (folder_name, asset_type)
    from collections import defaultdict
    grouped = defaultdict(list)
    for a in assets:
        folder_name = folders.get(a.folder_id, '(root)') if a.folder_id else '(root)'
        grouped[(folder_name, a.asset_type or 'misc')].append(a)

    if not assets:
        return 'No assets uploaded yet.'

    type_labels = {'image': 'Image', 'audio': 'Audio', 'video': 'Video', 'misc': 'File'}
    lines = []
    # Sort: root first, then alphabetical folder
    for folder_name in sorted(grouped_folders := {k[0] for k in grouped}, key=lambda x: (x != '(root)', x)):
        lines.append(f'\nFolder: {folder_name}')
        for atype, label in type_labels.items():
            bucket = grouped.get((folder_name, atype), [])
            if not bucket:
                continue
            lines.append(f'  {label}s:')
            for a in bucket:
                name = a.original_filename or a.stored_filename
                lines.append(f'    - {name}  →  {a.url}')
        # Any unlabelled types in this folder
        for (fn, atype), bucket in grouped.items():
            if fn == folder_name and atype not in type_labels:
                lines.append(f'  {atype.title()} files:')
                for a in bucket:
                    lines.append(f'    - {a.original_filename or a.stored_filename}  →  {a.url}')

    return '\n'.join(lines)


@app.route('/admin/code_section/<int:section_id>/ai_assist', methods=['POST'])
@login_required
@require_perm('code.ai')
def code_section_ai_assist(section_id):
    section = PageSection.query.get_or_404(section_id)
    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)

    if not is_owner(website):
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    data = request.get_json()
    agent_id = data.get('agent_id')
    prompt = (data.get('prompt') or '').strip()
    current_code = (data.get('current_code') or '').strip()

    if not agent_id:
        return _utf8_json({'success': False, 'error': 'No agent selected'}, 400)
    if not prompt:
        return _utf8_json({'success': False, 'error': 'Prompt is required'}, 400)

    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    # Render the full public page for context
    try:
        page_html = render_public_page(website, page)
        if len(page_html) > 40000:
            page_html = page_html[:40000] + '\n\n<!-- [page truncated for brevity] -->'
    except Exception as e:
        page_html = f'(page could not be rendered: {e})'

    asset_inventory = _build_asset_inventory(current_user.id)

    system_override = (
        "You are a web code assistant embedded in Uwebia, a website builder.\n"
        f"The user is editing a CODE SECTION whose wrapper element has the DOM id 'section-{section_id}'.\n"
        "The HTML/CSS/JS you write is injected as the ENTIRE CONTENT of that section wrapper.\n\n"
        "Scoping rules (critical — the same section type may appear multiple times on the page):\n"
        f"- ALL CSS selectors must be prefixed with '#section-{section_id}' so they only affect this section.\n"
        f"  Example: '#section-{section_id} h1 {{ color: red; }}'\n"
        "- ALL JavaScript must be wrapped in an IIFE: (function(){{ ... }})();\n"
        "  Inside the IIFE, declare every function and variable with const/let (arrow functions).\n"
        "  NEVER use 'function foo()' declarations — they hoist to global scope and collide across sections.\n"
        f"- To reference DOM elements inside this section from JS, use:\n"
        f"  document.querySelector('#section-{section_id} .my-class')\n"
        "  Never use getElementById with a hardcoded id — ids must be unique per page.\n\n"
        "Other rules:\n"
        "- Return ONLY raw HTML/CSS/JS. No explanations, no markdown, no code fences.\n"
        "- You MAY use <style> and <script> blocks.\n"
        "- Do NOT include <html>, <head>, or <body> tags.\n"
        "- OUTPUT RULE: Your response must be the full, complete code — existing code plus your changes. "
        "Copy every line of the existing code into your output, then integrate your changes. "
        "Never summarise, abbreviate, or replace code with placeholder comments.\n"
        "- ONLY use assets when the user explicitly asks. When used, reference exact URLs from the asset list."
    )

    if current_code:
        existing_block = (
            f"EXISTING CODE — you MUST include every line of this verbatim in your output, "
            f"with your changes integrated:\n{current_code}"
        )
    else:
        existing_block = "EXISTING CODE: (empty — write new code from scratch)"

    user_message = (
        f"Current full public page HTML for context:\n\n{page_html}\n\n"
        f"---\n\nAvailable assets (only use if the request explicitly asks for them):\n{asset_inventory}\n\n"
        f"---\n\n{existing_block}\n\n"
        f"---\n\nMODIFICATION REQUEST: {prompt}"
    )

    # Temporarily override system prompt for this call
    original_system = agent.system_prompt
    agent.system_prompt = system_override

    reply, error = _call_ai_agent(agent, [{'role': 'user', 'content': user_message}])

    agent.system_prompt = original_system  # restore (not committed)

    if error:
        return _utf8_json({'success': False, 'error': error}, 502)

    return _utf8_json({'success': True, 'code': _strip_code_fences(reply)})


# ── Page-level custom code ────────────────────────────────────────────────────

@app.route('/admin/page/<int:page_id>/custom_code', methods=['GET'])
@login_required
@require_perm('code.sections')
def get_page_custom_code(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    return _utf8_json({'success': True, 'code': page.custom_code or ''})


@app.route('/admin/page/<int:page_id>/save_custom_code', methods=['POST'])
@login_required
@require_perm('appearance.page_code')
@require_perm('code.sections')
def save_page_custom_code(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    data = request.get_json(force=True, silent=True) or {}
    page.custom_code = data.get('code', '') or None
    db.session.commit()
    return _utf8_json({'success': True})


@app.route('/admin/page/<int:page_id>/ai_assist_page_code', methods=['POST'])
@login_required
@require_perm('appearance.page_code')
@require_perm('code.sections')
def ai_assist_page_code(page_id):
    page = PublicPageContent.query.get_or_404(page_id)
    website = Website.query.get_or_404(page.website_id)
    if not is_owner(website):
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    data = request.get_json() or {}
    agent_id = data.get('agent_id')
    prompt = (data.get('prompt') or '').strip()
    current_code = (data.get('current_code') or '').strip()

    if not agent_id:
        return _utf8_json({'success': False, 'error': 'No agent selected'}, 400)
    if not prompt:
        return _utf8_json({'success': False, 'error': 'Prompt is required'}, 400)

    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    try:
        page_html = render_public_page(website, page)
        if len(page_html) > 50000:
            page_html = page_html[:50000] + '\n<!-- [truncated] -->'
    except Exception as e:
        page_html = f'(could not render: {e})'

    asset_inventory = _build_asset_inventory(current_user.id)

    system_override = (
        "You are a web code assistant embedded in Uwebia, a website builder.\n"
        "The user is editing PAGE-LEVEL code — HTML/CSS/JS injected at the end of <body> "
        "that affects the ENTIRE page. This is the right place for page-wide styles and behaviour; "
        "do NOT scope styles to individual sections here.\n\n"
        "Key page structure facts you MUST know:\n"
        "- The page background is controlled by the CSS variable --site-bg-color set on :root. "
        "To change it: :root { --site-bg-color: green; } or linear-gradient(...). "
        "You can also target .site-fixed-background directly with !important.\n"
        "- Page content is wrapped in <body class='public-page-body'>. Never set max-width or "
        "overflow on body — it will break the layout.\n"
        "- Each section has a unique DOM id 'section-{id}' (e.g. #section-42). "
        "Section groups use '.public-section-group'. Individual cells use '.public-section-cell'.\n\n"
        "JavaScript rules:\n"
        "- Wrap all JS in an IIFE: (function(){{ ... }})();\n"
        "- Use const/let and arrow functions only — no 'function foo()' declarations at top level.\n\n"
        "Rules (strict):\n"
        "- Return ONLY raw HTML/CSS/JS. No explanations, no markdown, no code fences.\n"
        "- You MAY use <style> and <script> blocks. Do NOT include <html>, <head>, or <body> tags.\n"
        "- Use real class names and IDs from the page HTML — never invent selectors.\n"
        "- OUTPUT RULE: Your response must be the full, complete code — existing code plus your changes. "
        "Copy every line of the existing code into your output, then integrate your changes. "
        "Never summarise, abbreviate, comment out, or replace existing code with a placeholder comment. "
        "A response shorter than the existing code (unless the user explicitly asked to remove something) "
        "is always wrong. Do not write comments like '/* existing styles remain */' — write the actual code.\n"
        "- ONLY use assets from the asset list when the user explicitly asks for them. "
        "Never include images, audio, or video unless the request clearly calls for it. "
        "When assets are requested, use the exact URLs provided. "
        "If the user references a folder name, use only assets listed under that folder."
    )

    if current_code:
        existing_block = (
            f"EXISTING PAGE CODE — you MUST include every line of this verbatim in your output, "
            f"with your changes integrated:\n{current_code}"
        )
    else:
        existing_block = "EXISTING PAGE CODE: (empty — write new code from scratch)"

    user_message = (
        f"Current full public page HTML for context:\n\n{page_html}\n\n"
        f"---\n\nAvailable assets (only use if the request explicitly asks for them; "
        f"folder names shown for reference):\n{asset_inventory}\n\n"
        f"---\n\n{existing_block}\n\n"
        f"---\n\nMODIFICATION REQUEST: {prompt}"
    )

    original_system = agent.system_prompt
    agent.system_prompt = system_override
    reply, error = _call_ai_agent(agent, [{'role': 'user', 'content': user_message}])
    agent.system_prompt = original_system

    if error:
        return _utf8_json({'success': False, 'error': error}, 502)
    return _utf8_json({'success': True, 'code': _strip_code_fences(reply)})


def _extract_api_error(response):
    """Pull the human-readable message out of an API error response body."""
    try:
        body = response.json()
        # Anthropic: {"type":"error","error":{"type":"...","message":"..."}}
        # OpenAI:    {"error":{"message":"...","type":"..."}}
        err = body.get('error', body)
        if isinstance(err, dict):
            return err.get('message') or err.get('error_description') or str(err)
        return str(body)
    except Exception:
        return response.text[:500] if response.text else 'No response body'


def _call_ai_agent(agent, messages):
    """Proxy a chat messages list to the configured AI provider. Returns (reply_text, error)."""
    import requests as req

    provider = agent.provider
    api_key = decrypt_api_key(agent.api_key or '')
    timeout = 60

    try:
        if provider == 'anthropic':
            url = 'https://api.anthropic.com/v1/messages'
            headers = {
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json',
            }
            payload = {
                'model': agent.model or 'claude-sonnet-4-6',
                'max_tokens': 2048,
                'messages': messages,
            }
            if agent.system_prompt:
                payload['system'] = agent.system_prompt
            r = req.post(url, headers=headers, json=payload, timeout=timeout)
            if not r.ok:
                return None, f'Anthropic {r.status_code}: {_extract_api_error(r)}'
            return r.json()['content'][0]['text'], None

        else:
            # OpenAI, OpenAI-compatible (Ollama, LM Studio, Groq, etc.)
            if provider == 'openai':
                base = 'https://api.openai.com'
            else:
                base = (agent.api_url or 'http://localhost:11434').rstrip('/')

            url = f'{base}/v1/chat/completions'
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'

            full_messages = []
            if agent.system_prompt:
                full_messages.append({'role': 'system', 'content': agent.system_prompt})
            full_messages.extend(messages)

            payload = {
                'model': agent.model or 'gpt-4o',
                'messages': full_messages,
                'max_tokens': 2048,
            }
            r = req.post(url, headers=headers, json=payload, timeout=timeout)
            if not r.ok:
                return None, f'API {r.status_code}: {_extract_api_error(r)}'
            return r.json()['choices'][0]['message']['content'], None

    except Exception as e:
        return None, str(e)


def _utf8_json(data, status=200):
    """Return a JSON response explicitly encoded as UTF-8 to handle any Unicode in AI output."""
    import json as _json
    body = _json.dumps(data, ensure_ascii=False).encode('utf-8')
    return Response(body, status=status, mimetype='application/json; charset=utf-8')


@app.route('/admin/ai-agents/<int:agent_id>/chat', methods=['POST'])
@login_required
@require_perm('ai_agents.chat')
def ai_agent_chat(agent_id):
    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)
    data = request.get_json()
    messages = data.get('messages', [])
    if not messages:
        return _utf8_json({'success': False, 'error': 'No messages provided'}, 400)
    reply, error = _call_ai_agent(agent, messages)
    if error:
        return _utf8_json({'success': False, 'error': error}, 502)
    return _utf8_json({'success': True, 'reply': reply})


@app.route('/admin/ai-agents/<int:agent_id>/test', methods=['POST'])
@login_required
@require_perm('ai_agents.use')
def test_ai_agent(agent_id):
    import requests as _req, base64 as _b64
    agent = AIAgent.query.get_or_404(agent_id)
    if Website.query.get_or_404(agent.website_id).user_id != current_user.root_user_id:
        return _utf8_json({'success': False, 'error': 'Unauthorized'}, 403)

    caps = agent.capabilities or 'chat'

    if caps == 'image':
        # Test image generation with a minimal prompt
        api_key = decrypt_api_key(agent.api_key or '')
        if agent.provider == 'openai':
            base_url = 'https://api.openai.com'
            model = agent.model or 'dall-e-3'
        else:
            base_url = (agent.api_url or '').rstrip('/')
            model = agent.model or 'dall-e-3'
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        try:
            r = _req.post(f'{base_url}/v1/images/generations',
                          json={'model': model, 'prompt': 'A small red circle', 'n': 1, 'size': '256x256'},
                          headers=headers, timeout=60)
            if r.ok:
                return _utf8_json({'success': True, 'reply': 'Image generation connection OK'})
            return _utf8_json({'success': False, 'error': _extract_api_error(r)})
        except Exception as e:
            return _utf8_json({'success': False, 'error': str(e)})

    # Chat test (capabilities == 'chat' or 'both')
    reply, error = _call_ai_agent(agent, [{'role': 'user', 'content': 'Reply with exactly: OK'}])
    if error:
        return _utf8_json({'success': False, 'error': error})
    return _utf8_json({'success': True, 'reply': reply})


@app.route('/admin/calendars')
@login_required
def admin_calendars_page():
    website = get_admin_website()
    calendars = []
    if website:
        calendars = Calendar.query.filter_by(website_id=website.id).order_by(Calendar.created_at.desc()).all()

    current_website = website
    current_website_pages = PublicPageContent.query.filter_by(website_id=website.id).order_by(
        PublicPageContent.sort_order, PublicPageContent.id
    ).all() if website else []
    page_id = None

    return render_template(
        'calendars.html',
        calendars=calendars,
        current_website=current_website,
        current_website_pages=current_website_pages,
        page_id=page_id
    )


@app.route('/admin/calendars/create', methods=['POST'])
@login_required
@require_perm('calendars.create')
def create_calendar():
    data = request.get_json()
    website = get_admin_website()
    if not website:
        return jsonify({'success': False, 'error': 'No website found'}), 400

    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400

    calendar = Calendar(
        name=name,
        description=(data.get('description') or '').strip(),
        website_id=website.id,
        styles=_parse_calendar_styles(data.get('styles')),
    )
    db.session.add(calendar)
    db.session.commit()
    return jsonify({'success': True, 'calendar': calendar.to_dict()}), 201


@app.route('/admin/calendars/<int:calendar_id>/update', methods=['POST'])
@login_required
@require_perm('calendars.edit')
def update_calendar(calendar_id):
    calendar = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(calendar.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.get_json()
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Name is required'}), 400

    calendar.name = name
    calendar.description = (data.get('description') or '').strip()
    calendar.styles = _parse_calendar_styles(data.get('styles'))
    db.session.commit()
    return jsonify({'success': True, 'calendar': calendar.to_dict()})


@app.route('/admin/calendars/<int:calendar_id>/delete', methods=['POST'])
@login_required
def delete_calendar_route(calendar_id):
    calendar = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(calendar.website_id)
    if not is_owner(website):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    db.session.delete(calendar)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/admin/calendars/<int:calendar_id>/add_event', methods=['POST'])
@login_required
@require_perm('calendars.events')
def add_calendar_event(calendar_id):
    calendar = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(calendar.website_id)
    if not is_owner(website):
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        local_timezone = pytz.timezone('America/Chicago')

        start = _parse_event_datetime(data.get('start'), local_timezone)
        end = _parse_event_datetime(data.get('end'), local_timezone)

        if not start:
            return jsonify({'error': 'Start date is required'}), 400

        event = CalendarEvent(
            title=data.get('title'),
            description=data.get('description'),
            start=start,
            end=end,
            background_color=data.get('backgroundColor'),
            calendar_id=calendar_id
        )
        db.session.add(event)
        db.session.commit()
        return jsonify({'message': 'Event added successfully', 'event': event.to_dict()}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/admin/calendars/<int:calendar_id>/update_event', methods=['POST'])
@login_required
@require_perm('calendars.events')
def update_calendar_event(calendar_id):
    calendar = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(calendar.website_id)
    if not is_owner(website):
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        event_id = data.get('id')
        if not event_id:
            return jsonify({'message': 'Event id is required'}), 400

        event = CalendarEvent.query.filter_by(id=event_id, calendar_id=calendar_id).first()
        if not event:
            return jsonify({'message': 'Event not found'}), 404

        local_timezone = pytz.timezone('America/Chicago')
        start = _parse_event_datetime(data.get('start'), local_timezone)
        end = _parse_event_datetime(data.get('end'), local_timezone)

        event.title = data.get('title', event.title)
        event.description = data.get('description', event.description)
        if start:
            event.start = start
        event.end = end
        event.background_color = data.get('backgroundColor', event.background_color)

        db.session.commit()
        return jsonify({'message': 'Event updated successfully', 'event': event.to_dict()}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/admin/calendars/<int:calendar_id>/delete_event', methods=['POST'])
@login_required
@require_perm('calendars.events')
def delete_calendar_event(calendar_id):
    calendar = Calendar.query.get_or_404(calendar_id)
    website = Website.query.get_or_404(calendar.website_id)
    if not is_owner(website):
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        event_id = data.get('id')
        if not event_id:
            return jsonify({'message': 'Event id is required'}), 400

        event = CalendarEvent.query.filter_by(id=event_id, calendar_id=calendar_id).first()
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


@app.route('/forum')
def public_forum():
    website = get_live_website()

    if not website:
        return render_template('no_site_found.html'), 404

    if not website.forum_enabled:
        return "Forum is disabled", 404

    public_user = get_public_user()

    if website.forum_require_login_to_view and not public_user:
        return redirect(url_for('public_forum_login', next=url_for('public_forum')))

    sort = request.args.get('sort', 'relevant')

    threads_query = ForumThread.query.filter(
        ForumThread.website_id == website.id,
        ForumThread.is_hidden == False
    )

    if sort == 'newest':
        threads_query = threads_query.order_by(
            ForumThread.is_pinned.desc(),
            ForumThread.created_at.desc()
        )

    elif sort == 'oldest':
        threads_query = threads_query.order_by(
            ForumThread.is_pinned.desc(),
            ForumThread.created_at.asc()
        )

    elif sort == 'most_upvoted':
        threads_query = threads_query.order_by(
            ForumThread.is_pinned.desc(),
            ForumThread.vote_count_cached.desc(),
            ForumThread.updated_at.desc()
        )

    elif sort == 'most_active':
        threads_query = threads_query.order_by(
            ForumThread.is_pinned.desc(),
            ForumThread.reply_count.desc(),
            ForumThread.updated_at.desc()
        )

    else:
        sort = 'relevant'
        threads_query = threads_query.order_by(
            ForumThread.is_pinned.desc(),
            ForumThread.vote_count_cached.desc(),
            ForumThread.reply_count.desc(),
            ForumThread.updated_at.desc(),
            ForumThread.created_at.desc()
        )

    page = request.args.get('page', 1, type=int)
    per_page = 25

    threads_pagination = threads_query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    threads = threads_pagination.items

    content = {
        'current_page_url': url_for('public_forum')
    }

    return render_template(
        'public_forum.html',
        website=website,
        threads=threads,
        threads_pagination=threads_pagination,
        public_user=public_user,
        current_sort=sort,
        content=content
    )


@app.route('/forum/thread/<int:thread_id>/vote', methods=['POST'])
def public_forum_vote_thread(thread_id):
    website = get_live_website()

    if not website or not website.forum_enabled:
        return jsonify({'success': False, 'message': 'Forum is disabled.'}), 404

    public_user = get_public_user()

    if not public_user:
        return jsonify({
            'success': False,
            'message': 'Please log in to upvote.'
        }), 401

    thread = ForumThread.query.filter_by(
        id=thread_id,
        website_id=website.id,
        is_hidden=False
    ).first_or_404()

    existing_vote = ForumThreadVote.query.filter_by(
        thread_id=thread.id,
        public_user_id=public_user.id
    ).first()

    if existing_vote:
        db.session.delete(existing_vote)
        thread.vote_count_cached = max(0, (thread.vote_count_cached or 0) - 1)
        voted = False
    else:
        vote = ForumThreadVote(
            thread_id=thread.id,
            website_id=website.id,
            public_user_id=public_user.id
        )
        db.session.add(vote)
        thread.vote_count_cached = (thread.vote_count_cached or 0) + 1
        voted = True

    db.session.commit()

    return jsonify({
        'success': True,
        'voted': voted,
        'vote_count': thread.vote_count_cached or 0
    })


@app.route('/forum/reply/<int:reply_id>/vote', methods=['POST'])
def public_forum_vote_reply(reply_id):
    website = get_live_website()

    if not website or not website.forum_enabled:
        return jsonify({'success': False, 'message': 'Forum is disabled.'}), 404

    public_user = get_public_user()

    if not public_user:
        return jsonify({
            'success': False,
            'message': 'Please log in to upvote.'
        }), 401

    reply = ForumReply.query.filter_by(
        id=reply_id,
        website_id=website.id,
        is_hidden=False
    ).first_or_404()

    existing_vote = ForumReplyVote.query.filter_by(
        reply_id=reply.id,
        public_user_id=public_user.id
    ).first()

    if existing_vote:
        db.session.delete(existing_vote)
        reply.vote_count_cached = max(0, (reply.vote_count_cached or 0) - 1)
        voted = False
    else:
        vote = ForumReplyVote(
            reply_id=reply.id,
            website_id=website.id,
            public_user_id=public_user.id
        )
        db.session.add(vote)
        reply.vote_count_cached = (reply.vote_count_cached or 0) + 1
        voted = True

    db.session.commit()

    return jsonify({
        'success': True,
        'voted': voted,
        'vote_count': reply.vote_count_cached or 0
    })


@app.route('/account/register', methods=['GET', 'POST'])
@app.route('/forum/register', methods=['GET', 'POST'])
def public_forum_register():
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip().lower()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        if not username or not email or not password:
            flash('Please fill out all fields.', 'error')
            return redirect(url_for('public_forum_register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(url_for('public_forum_register'))

        existing = PublicUser.query.filter(
            PublicUser.website_id == website.id,
            or_(
                PublicUser.username == username,
                PublicUser.email == email
            )
        ).first()

        if existing:
            flash('That username or email is already in use.', 'error')
            return redirect(url_for('public_forum_register'))

        public_user = PublicUser(
            website_id=website.id,
            username=username,
            email=email,
            email_verified=not website.forum_account_verification_enabled
        )
        public_user.set_password(password)

        db.session.add(public_user)
        db.session.commit()

        if website.forum_account_verification_enabled:
            try:
                send_public_user_verification_email(public_user)
                flash('Account created. Please check your email to verify your account.', 'success')
            except Exception as e:
                print(f'Public user verification email failed: {e}')
                flash(
                    'Account created, but the verification email could not be sent. Please contact the site owner.',
                    'error'
                )

            if website.forum_allow_unverified_login:
                public_user_login(public_user)

            return redirect(
                url_for(
                    'public_forum_login',
                    next=request.args.get('next') or url_for('home_page')
                )
            )

        public_user_login(public_user)

        next_url = request.args.get('next')

        if not next_url:
            if website.forum_enabled:
                next_url = url_for('public_forum')
            else:
                next_url = url_for('home_page')

        return redirect(next_url)

    content = {
        'current_page_url': url_for('public_forum_register')
    }

    return render_template(
        'public_forum_register.html',
        website=website,
        public_user=get_public_user(),
        content=content
    )


@app.route('/account/login', methods=['GET', 'POST'])
@app.route('/forum/login', methods=['GET', 'POST'])
def public_forum_login():
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    if request.method == 'POST':
        login_value = (request.form.get('login') or '').strip().lower()
        password = request.form.get('password') or ''

        public_user = PublicUser.query.filter(
            PublicUser.website_id == website.id,
            or_(
                PublicUser.username == login_value,
                PublicUser.email == login_value
            )
        ).first()

        if not public_user or not public_user.check_password(password):
            flash('Invalid username/email or password.', 'error')
            return redirect(url_for('public_forum_login'))

        if public_user.is_banned or not public_user.is_active_public:
            flash('This account cannot access the forum.', 'error')
            return redirect(url_for('public_forum_login'))

        if (
                website.forum_account_verification_enabled
                and not website.forum_allow_unverified_login
                and not public_user.email_verified
        ):
            flash('Please verify your email before logging in.', 'error')
            return redirect(url_for('public_forum_resend_verification'))

        public_user_login(public_user)

        next_url = request.args.get('next')

        if not next_url:
            if website.forum_enabled:
                next_url = url_for('public_forum')
            else:
                next_url = url_for('home_page')

        return redirect(next_url)

    content = {
        'current_page_url': url_for('public_forum_login')
    }

    return render_template(
        'public_forum_login.html',
        website=website,
        public_user=get_public_user(),
        content=content
    )


@app.route('/account/forgot-password', methods=['GET', 'POST'])
@app.route('/forum/forgot-password', methods=['GET', 'POST'])
def public_forum_forgot_password():
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()

        generic_message = (
            'If that email matches an account and email sending is configured, '
            'a password reset link has been sent.'
        )

        public_user = PublicUser.query.filter_by(
            website_id=website.id,
            email=email
        ).first()

        if public_user and not public_user.is_banned and public_user.is_active_public:
            try:
                send_public_user_password_reset_email(public_user)
            except Exception as e:
                print(f'Public forum password reset email failed: {e}')

        flash(generic_message, 'success')
        return redirect(url_for('public_forum_login'))

    content = {
        'current_page_url': url_for('public_forum_forgot_password')
    }

    return render_template(
        'public_forum_forgot_password.html',
        website=website,
        public_user=get_public_user(),
        content=content
    )


@app.route('/account/reset-password/<token>', methods=['GET', 'POST'])
@app.route('/forum/reset-password/<token>', methods=['GET', 'POST'])
def public_forum_reset_password(token):
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    public_user, error = verify_public_user_password_reset_token(token)

    if error:
        flash(error, 'error')
        return redirect(url_for('public_forum_login'))

    if public_user.website_id != website.id:
        return "Not Found", 404

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not password:
            flash('Please enter a new password.', 'error')
            return redirect(request.path)

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return redirect(request.path)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(request.path)

        public_user.set_password(password)

        # If verification is enabled, a password-reset-confirmed user
        # can reasonably be treated as email verified.
        if website.forum_account_verification_enabled:
            public_user.email_verified = True
            public_user.email_verified_at = datetime.now(timezone.utc).replace(tzinfo=None)

        db.session.commit()

        public_user_logout()

        flash('Password updated successfully. Please log in.', 'success')
        return redirect(url_for('public_forum_login'))

    content = {
        'current_page_url': url_for('public_forum_reset_password', token=token)
    }

    return render_template(
        'public_forum_reset_password.html',
        website=website,
        public_user=get_public_user(),
        token=token,
        content=content
    )


@app.route('/account/verify-email/<token>')
@app.route('/forum/verify-email/<token>')
def public_forum_verify_email(token):
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    public_user, error = verify_public_user_verification_token(token)

    if error:
        flash(error, 'error')
        return redirect(url_for('public_forum_login'))

    if public_user.website_id != website.id:
        return "Not Found", 404

    public_user.email_verified = True
    public_user.email_verified_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.session.commit()

    flash('Your email has been verified. You can now log in.', 'success')
    return redirect(url_for('public_forum_login'))


@app.route('/account/resend-verification', methods=['GET', 'POST'])
@app.route('/forum/resend-verification', methods=['GET', 'POST'])
def public_forum_resend_verification():
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()

        generic_message = (
            'If that email matches an unverified account, '
            'a new verification email has been sent.'
        )

        public_user = PublicUser.query.filter_by(
            website_id=website.id,
            email=email
        ).first()

        if (
                public_user
                and not public_user.email_verified
                and not public_user.is_banned
                and public_user.is_active_public
        ):
            try:
                send_public_user_verification_email(public_user)
            except Exception as e:
                print(f'Public forum verification resend failed: {e}')

        flash(generic_message, 'success')
        return redirect(url_for('public_forum_login'))

    content = {
        'current_page_url': url_for('public_forum_resend_verification')
    }

    return render_template(
        'public_forum_resend_verification.html',
        website=website,
        public_user=get_public_user(),
        content=content
    )


@app.route('/forum/logout', methods=['POST'])
@app.route('/account/logout', methods=['POST'])
def public_forum_logout():
    website = get_live_website()

    public_user_logout()

    next_url = request.form.get('next') or request.referrer

    if next_url:
        return redirect(next_url)

    if website and website.forum_enabled:
        return redirect(url_for('public_forum'))

    return redirect(url_for('home_page'))


@app.route('/forum/thread/new', methods=['GET', 'POST'])
def public_forum_new_thread():
    website = get_live_website()

    if not website or not website.forum_enabled:
        return "Forum is disabled", 404

    public_user = get_public_user()

    if website.forum_require_login_to_post and not public_user:
        return redirect(url_for('public_forum_login', next=url_for('public_forum_new_thread')))

    if request.method == 'POST':
        title = (request.form.get('title') or '').strip()
        body = (request.form.get('body') or '').strip()

        if not title or not body:
            flash('Please enter a title and message.', 'error')
            return redirect(url_for('public_forum_new_thread'))

        thread = ForumThread(
            website_id=website.id,
            public_user_id=public_user.id if public_user else None,
            title=title[:180],
            body=body,
            ip_address=get_request_ip(),
            user_agent=request.headers.get('User-Agent')
        )

        db.session.add(thread)
        db.session.commit()

        return redirect(url_for('public_forum_thread', thread_id=thread.id))

    content = {
        'current_page_url': url_for('public_forum_new_thread')
    }

    return render_template(
        'public_forum_new_thread.html',
        website=website,
        public_user=public_user,
        content=content
    )


@app.route('/forum/thread/<int:thread_id>', methods=['GET', 'POST'])
def public_forum_thread(thread_id):
    website = get_live_website()

    if not website or not website.forum_enabled:
        return "Forum is disabled", 404

    public_user = get_public_user()

    thread = ForumThread.query.filter_by(
        id=thread_id,
        website_id=website.id
    ).first_or_404()

    if thread.is_hidden:
        return "Thread not found", 404

    if website.forum_require_login_to_view and not public_user:
        return redirect(url_for('public_forum_login', next=url_for('public_forum_thread', thread_id=thread.id)))

    if request.method == 'POST':
        if thread.is_locked:
            flash('This thread is locked.', 'error')
            return redirect(url_for('public_forum_thread', thread_id=thread.id))

        if website.forum_require_login_to_post and not public_user:
            return redirect(url_for('public_forum_login', next=url_for('public_forum_thread', thread_id=thread.id)))

        body = (request.form.get('body') or '').strip()

        if not body:
            flash('Please enter a reply.', 'error')
            return redirect(url_for('public_forum_thread', thread_id=thread.id))

        reply = ForumReply(
            thread_id=thread.id,
            website_id=website.id,
            public_user_id=public_user.id if public_user else None,
            body=body,
            ip_address=get_request_ip(),
            user_agent=request.headers.get('User-Agent')
        )

        thread.reply_count = (thread.reply_count or 0) + 1
        thread.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

        db.session.add(reply)
        db.session.commit()

        return redirect(url_for('public_forum_thread', thread_id=thread.id))

    reply_page = request.args.get('reply_page', 1, type=int)
    replies_per_page = 50

    replies_pagination = ForumReply.query.filter_by(
        thread_id=thread.id,
        is_hidden=False
    ).order_by(
        ForumReply.created_at.asc()
    ).paginate(
        page=reply_page,
        per_page=replies_per_page,
        error_out=False
    )

    replies = replies_pagination.items

    content = {
        'current_page_url': url_for('public_forum_thread', thread_id=thread.id)
    }

    return render_template(
        'public_forum_thread.html',
        website=website,
        thread=thread,
        replies=replies,
        replies_pagination=replies_pagination,
        public_user=public_user,
        content=content
    )


@app.route('/admin/forum')
@login_required
def admin_forum():
    website = Website.query.filter_by(user_id=current_user.root_user_id).first_or_404()

    threads = ForumThread.query.filter_by(
        website_id=website.id
    ).order_by(
        ForumThread.created_at.desc()
    ).all()

    users = PublicUser.query.filter_by(
        website_id=website.id
    ).order_by(PublicUser.created_at.desc()).all()

    return render_template(
        'admin_forum.html',
        website=website,
        threads=threads,
        users=users,
        email_settings=get_email_settings()
    )


@app.route('/admin/forum/settings', methods=['POST'])
@login_required
def update_forum_settings():
    website = Website.query.filter_by(user_id=current_user.root_user_id).first_or_404()

    website.forum_enabled = request.form.get('forum_enabled') == 'on'
    website.forum_show_in_navbar = request.form.get('forum_show_in_navbar') == 'on'
    website.forum_require_login_to_view = request.form.get('forum_require_login_to_view') == 'on'
    website.forum_require_login_to_post = request.form.get('forum_require_login_to_post') == 'on'
    website.forum_title = (request.form.get('forum_title') or 'Forum').strip()[:120]
    website.forum_description = (request.form.get('forum_description') or '').strip()
    website.forum_account_verification_enabled = (
            request.form.get('forum_account_verification_enabled') == 'on'
    )

    website.forum_allow_unverified_login = (
            request.form.get('forum_allow_unverified_login') == 'on'
    )

    db.session.commit()

    flash('Forum settings saved.', 'success')
    return redirect(url_for('admin_forum'))


@app.route('/admin/forum/thread/<int:thread_id>/moderate', methods=['POST'])
@login_required
@require_perm('forum.moderate')
def moderate_forum_thread(thread_id):
    website = Website.query.filter_by(user_id=current_user.root_user_id).first_or_404()

    thread = ForumThread.query.filter_by(
        id=thread_id,
        website_id=website.id
    ).first_or_404()

    action = request.form.get('action')

    if action == 'hide':
        thread.is_hidden = True
    elif action == 'unhide':
        thread.is_hidden = False
    elif action == 'lock':
        thread.is_locked = True
    elif action == 'unlock':
        thread.is_locked = False
    elif action == 'pin':
        thread.is_pinned = True
    elif action == 'unpin':
        thread.is_pinned = False
    elif action == 'delete':
        db.session.delete(thread)
        db.session.commit()
        return redirect(url_for('admin_forum'))

    db.session.commit()
    return redirect(url_for('admin_forum'))


@app.route('/admin/forum/reply/<int:reply_id>/moderate', methods=['POST'])
@login_required
@require_perm('forum.moderate')
def moderate_forum_reply(reply_id):
    website = Website.query.filter_by(user_id=current_user.root_user_id).first_or_404()

    reply = ForumReply.query.filter_by(
        id=reply_id,
        website_id=website.id
    ).first_or_404()

    thread = ForumThread.query.filter_by(
        id=reply.thread_id,
        website_id=website.id
    ).first()

    action = request.form.get('action')

    if action == 'hide':
        if not reply.is_hidden:
            reply.is_hidden = True

            if thread:
                thread.reply_count = max(0, (thread.reply_count or 0) - 1)

    elif action == 'unhide':
        if reply.is_hidden:
            reply.is_hidden = False

            if thread:
                thread.reply_count = (thread.reply_count or 0) + 1

    elif action == 'delete':
        was_visible = not reply.is_hidden

        if was_visible and thread:
            thread.reply_count = max(0, (thread.reply_count or 0) - 1)

        db.session.delete(reply)
        db.session.commit()

        return redirect(url_for('admin_forum'))

    db.session.commit()
    return redirect(url_for('admin_forum'))


def update_comments_section(section, form_data):
    def clean(value, fallback=''):
        return (value or fallback).strip()

    def safe_int(value, fallback, min_value=None, max_value=None):
        try:
            number = int(value or fallback)
        except (TypeError, ValueError):
            number = fallback

        if min_value is not None:
            number = max(min_value, number)

        if max_value is not None:
            number = min(max_value, number)

        return number

    section.content = {
        'title': clean(form_data.get('comments_title'), 'Comments'),
        'description': clean(form_data.get('comments_description'), ''),
        'enabled': form_data.get('comments_enabled') == 'on',
        'require_login': form_data.get('comments_require_login') == 'on',
        'allow_anonymous': form_data.get('comments_allow_anonymous') == 'on',
        'manual_approval': form_data.get('comments_manual_approval') == 'on',
        'show_comment_count': form_data.get('comments_show_count') == 'on',
        'comments_per_page': safe_int(form_data.get('comments_per_page'), 25, 5, 100),
    }

    section.section_type = 'comments'

    return section


@app.route('/section/<int:section_id>/comment', methods=['POST'])
def submit_page_comment(section_id):
    section = PageSection.query.get_or_404(section_id)

    if section.section_type != 'comments':
        return jsonify({
            'success': False,
            'message': 'This section does not accept comments.'
        }), 400

    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)

    if not page.site_active_status:
        return jsonify({
            'success': False,
            'message': 'This page is not published.'
        }), 404

    settings = section.content or {}

    if not settings.get('enabled', True):
        return jsonify({
            'success': False,
            'message': 'Comments are disabled for this section.'
        }), 403

    public_user = get_public_user()

    require_login = settings.get('require_login', False)
    allow_anonymous = settings.get('allow_anonymous', True)

    if require_login and not public_user:
        return jsonify({
            'success': False,
            'requires_login': True,
            'message': 'Please log in to comment.'
        }), 401

    body = (request.form.get('comment_body') or '').strip()
    anonymous_name = (request.form.get('comment_name') or '').strip()

    if not body:
        return jsonify({
            'success': False,
            'message': 'Please enter a comment.'
        }), 400

    if len(body) > 3000:
        return jsonify({
            'success': False,
            'message': 'Comment is too long.'
        }), 400

    if public_user:
        display_name = public_user.username
    else:
        if not allow_anonymous:
            return jsonify({
                'success': False,
                'requires_login': True,
                'message': 'Please log in to comment.'
            }), 401

        if not anonymous_name:
            return jsonify({
                'success': False,
                'message': 'Please enter your name.'
            }), 400

        display_name = anonymous_name[:120]

    comment = PageComment(
        website_id=website.id,
        page_id=page.id,
        section_id=section.id,
        public_user_id=public_user.id if public_user else None,
        display_name=display_name,
        body=body,
        is_approved=not settings.get('manual_approval', False),
        ip_address=get_request_ip(),
        user_agent=request.headers.get('User-Agent')
    )

    db.session.add(comment)
    db.session.commit()

    if comment.is_approved:
        message = 'Comment posted.'
    else:
        message = 'Comment submitted and awaiting approval.'

    return jsonify({
        'success': True,
        'message': message,
        'approved': comment.is_approved,
        'comment': {
            'id': comment.id,
            'display_name': comment.display_name,
            'body': comment.body,
            'created_at': comment.created_at.strftime('%b %d, %Y %I:%M %p')
        }
    })


def serialize_page_comment(comment):
    return {
        'id': comment.id,
        'section_id': comment.section_id,
        'page_id': comment.page_id,
        'website_id': comment.website_id,
        'public_user_id': comment.public_user_id,
        'display_name': comment.display_name,
        'body': comment.body,
        'is_hidden': bool(comment.is_hidden),
        'is_approved': bool(comment.is_approved),
        'created_at': comment.created_at.strftime('%b %d, %Y %I:%M %p') if comment.created_at else '',
        'author_username': comment.author.username if comment.author else None,
        'like_count': comment.like_count_cached or 0,
        'ip_address': comment.ip_address or '',
    }


@app.route('/admin/section/<int:section_id>/comments', methods=['GET'])
@login_required
def get_section_comments(section_id):
    section = PageSection.query.get_or_404(section_id)

    page = PublicPageContent.query.get_or_404(section.page_content_id)
    website = Website.query.get_or_404(page.website_id)

    if not is_owner(website):
        return jsonify({
            'success': False,
            'message': 'Unauthorized.'
        }), 403

    if section.section_type != 'comments':
        return jsonify({
            'success': False,
            'message': 'This section is not a comments section.'
        }), 400

    status = request.args.get('status', 'all')
    page_number = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = max(5, min(per_page, 100))

    query = PageComment.query.filter_by(
        section_id=section.id
    )

    if status == 'pending':
        query = query.filter(PageComment.is_approved == False)
    elif status == 'approved':
        query = query.filter(
            PageComment.is_approved == True,
            PageComment.is_hidden == False
        )
    elif status == 'hidden':
        query = query.filter(PageComment.is_hidden == True)
    elif status == 'visible':
        query = query.filter(
            PageComment.is_hidden == False,
            PageComment.is_approved == True
        )

    pagination = query.order_by(
        PageComment.created_at.desc()
    ).paginate(
        page=page_number,
        per_page=per_page,
        error_out=False
    )

    pending_count = PageComment.query.filter_by(
        section_id=section.id,
        is_approved=False
    ).count()

    hidden_count = PageComment.query.filter_by(
        section_id=section.id,
        is_hidden=True
    ).count()

    total_count = PageComment.query.filter_by(
        section_id=section.id
    ).count()

    visible_count = PageComment.query.filter_by(
        section_id=section.id,
        is_hidden=False,
        is_approved=True
    ).count()

    return jsonify({
        'success': True,
        'comments': [
            serialize_page_comment(comment)
            for comment in pagination.items
        ],
        'pagination': {
            'page': pagination.page,
            'pages': pagination.pages,
            'has_prev': pagination.has_prev,
            'has_next': pagination.has_next,
            'prev_num': pagination.prev_num,
            'next_num': pagination.next_num,
            'total': pagination.total
        },
        'counts': {
            'total': total_count,
            'visible': visible_count,
            'pending': pending_count,
            'hidden': hidden_count
        }
    })


@app.route('/admin/page-comment/<int:comment_id>/moderate-json', methods=['POST'])
@login_required
@require_perm('comments.moderate')
def moderate_page_comment_json(comment_id):
    comment = PageComment.query.get_or_404(comment_id)

    website = Website.query.filter_by(
        id=comment.website_id,
        user_id=current_user.id
    ).first_or_404()

    data = request.get_json(silent=True) or {}
    action = data.get('action') or request.form.get('action')

    if action == 'hide':
        comment.is_hidden = True

    elif action == 'unhide':
        comment.is_hidden = False

    elif action == 'approve':
        comment.is_approved = True
        comment.is_hidden = False

    elif action == 'unapprove':
        comment.is_approved = False

    elif action == 'delete':
        section_id = comment.section_id
        db.session.delete(comment)
        db.session.commit()

        return jsonify({
            'success': True,
            'deleted': True,
            'section_id': section_id,
            'message': 'Comment deleted.'
        })

    else:
        return jsonify({
            'success': False,
            'message': 'Invalid moderation action.'
        }), 400

    db.session.commit()

    return jsonify({
        'success': True,
        'deleted': False,
        'message': 'Comment updated.',
        'comment': serialize_page_comment(comment)
    })


@app.route('/admin/page-comment/<int:comment_id>/moderate', methods=['POST'])
@login_required
@require_perm('comments.moderate')
def moderate_page_comment(comment_id):
    comment = PageComment.query.get_or_404(comment_id)

    website = Website.query.filter_by(
        id=comment.website_id,
        user_id=current_user.id
    ).first_or_404()

    action = request.form.get('action')

    if action == 'hide':
        comment.is_hidden = True

    elif action == 'unhide':
        comment.is_hidden = False

    elif action == 'approve':
        comment.is_approved = True

    elif action == 'unapprove':
        comment.is_approved = False

    elif action == 'delete':
        db.session.delete(comment)
        db.session.commit()

        return redirect(request.referrer or url_for('dashboard'))

    db.session.commit()

    return redirect(request.referrer or url_for('dashboard'))


def website_uses_public_accounts(website):
    if not website:
        return False

    if website.forum_enabled:
        return True

    comments_section_exists = PageSection.query.join(
        PublicPageContent,
        PageSection.page_content_id == PublicPageContent.id
    ).filter(
        PublicPageContent.website_id == website.id,
        PageSection.section_type == 'comments'
    ).first() is not None

    return comments_section_exists


def generate_public_user_password_reset_token(public_user):
    serializer = get_recovery_serializer()

    return serializer.dumps(
        {
            'public_user_id': public_user.id,
            'website_id': public_user.website_id,
            'purpose': 'public_user_password_reset'
        },
        salt='uwebia-public-user-password-reset'
    )


@app.route('/account/change-password', methods=['GET', 'POST'])
def public_account_change_password():
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return "Public accounts are not enabled for this site.", 404

    public_user = get_public_user()

    if not public_user:
        return redirect(url_for(
            'public_forum_login',
            next=url_for('public_account_change_password')
        ))

    if request.method == 'POST':
        current_password = request.form.get('current_password') or ''
        new_password = request.form.get('new_password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not public_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('public_account_change_password'))

        if len(new_password) < 8:
            flash('New password must be at least 8 characters.', 'error')
            return redirect(url_for('public_account_change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('public_account_change_password'))

        public_user.set_password(new_password)
        db.session.commit()

        flash('Password updated successfully.', 'success')
        return redirect(url_for('home_page'))

    content = {
        'current_page_url': url_for('public_account_change_password')
    }

    return render_template(
        'public_account_change_password.html',
        website=website,
        public_user=public_user,
        content=content
    )


def verify_public_user_password_reset_token(token, max_age_seconds=1800):
    serializer = get_recovery_serializer()

    try:
        data = serializer.loads(
            token,
            salt='uwebia-public-user-password-reset',
            max_age=max_age_seconds
        )
    except SignatureExpired:
        return None, 'This password reset link has expired.'
    except BadSignature:
        return None, 'This password reset link is invalid.'

    if data.get('purpose') != 'public_user_password_reset':
        return None, 'This password reset link is invalid.'

    public_user = PublicUser.query.filter_by(
        id=data.get('public_user_id'),
        website_id=data.get('website_id')
    ).first()

    if not public_user:
        return None, 'This password reset link is invalid.'

    return public_user, None


def generate_public_user_verification_token(public_user):
    serializer = get_recovery_serializer()

    return serializer.dumps(
        {
            'public_user_id': public_user.id,
            'website_id': public_user.website_id,
            'purpose': 'public_user_email_verification'
        },
        salt='uwebia-public-user-email-verification'
    )


def verify_public_user_verification_token(token, max_age_seconds=86400):
    serializer = get_recovery_serializer()

    try:
        data = serializer.loads(
            token,
            salt='uwebia-public-user-email-verification',
            max_age=max_age_seconds
        )
    except SignatureExpired:
        return None, 'This verification link has expired.'
    except BadSignature:
        return None, 'This verification link is invalid.'

    if data.get('purpose') != 'public_user_email_verification':
        return None, 'This verification link is invalid.'

    public_user = PublicUser.query.filter_by(
        id=data.get('public_user_id'),
        website_id=data.get('website_id')
    ).first()

    if not public_user:
        return None, 'This verification link is invalid.'

    return public_user, None


def send_public_user_password_reset_email(public_user):
    token = generate_public_user_password_reset_token(public_user)

    reset_url = url_for(
        'public_forum_reset_password',
        token=token,
        _external=True
    )

    subject = f'Reset your {public_user.website.name} account password'

    body = f"""A password reset was requested for your account.

Reset your password here:
{reset_url}

This link expires in 30 minutes.

If you did not request this, you can ignore this email.
"""

    send_account_recovery_email(public_user.email, subject, body)

    public_user.password_reset_requested_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()


def send_public_user_verification_email(public_user):
    token = generate_public_user_verification_token(public_user)

    verification_url = url_for(
        'public_forum_verify_email',
        token=token,
        _external=True
    )

    subject = f'Verify your {public_user.website.name} forum account'

    body = f"""Welcome to the forum.

Verify your email address here:
{verification_url}

This link expires in 24 hours.

If you did not create this account, you can ignore this email.
"""

    send_account_recovery_email(public_user.email, subject, body)

    public_user.verification_email_sent_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()


@app.route('/comment/<int:comment_id>/like', methods=['POST'])
def toggle_page_comment_like(comment_id):
    website = get_live_website()

    if not website or not website_uses_public_accounts(website):
        return jsonify({
            'success': False,
            'message': 'Public accounts are not enabled.'
        }), 404

    public_user = get_public_user()

    if not public_user:
        return jsonify({
            'success': False,
            'requires_login': True,
            'message': 'Please log in to like comments.'
        }), 401

    comment = PageComment.query.filter_by(
        id=comment_id,
        is_hidden=False,
        is_approved=True
    ).first_or_404()

    if comment.website_id != website.id:
        return jsonify({
            'success': False,
            'message': 'Comment not found.'
        }), 404

    existing_like = PageCommentLike.query.filter_by(
        comment_id=comment.id,
        public_user_id=public_user.id
    ).first()

    if existing_like:
        db.session.delete(existing_like)
        comment.like_count_cached = max(0, (comment.like_count_cached or 0) - 1)
        liked = False
    else:
        like = PageCommentLike(
            comment_id=comment.id,
            website_id=comment.website_id,
            section_id=comment.section_id,
            public_user_id=public_user.id
        )

        db.session.add(like)
        comment.like_count_cached = (comment.like_count_cached or 0) + 1
        liked = True

    db.session.commit()

    return jsonify({
        'success': True,
        'liked': liked,
        'like_count': comment.like_count_cached or 0
    })


@app.route('/admin/forum/user/<int:public_user_id>/moderate', methods=['POST'])
@login_required
def moderate_public_user(public_user_id):
    website = Website.query.filter_by(user_id=current_user.root_user_id).first_or_404()

    public_user = PublicUser.query.filter_by(
        id=public_user_id,
        website_id=website.id
    ).first_or_404()

    action = request.form.get('action')

    if action == 'ban':
        public_user.is_banned = True
    elif action == 'unban':
        public_user.is_banned = False
    elif action == 'deactivate':
        public_user.is_active_public = False
    elif action == 'activate':
        public_user.is_active_public = True

    db.session.commit()
    return redirect(url_for('admin_forum'))


def get_public_user():
    public_user_id = session.get('public_user_id')
    website_id = session.get('public_user_website_id')

    if not public_user_id or not website_id:
        return None

    return PublicUser.query.filter_by(
        id=public_user_id,
        website_id=website_id,
        is_banned=False,
        is_active_public=True
    ).first()


@app.context_processor
def inject_public_account_context():
    website = get_live_website()
    public_user = get_public_user() if website else None

    return {
        'navbar_public_user': public_user,
        'navbar_public_accounts_enabled': website_uses_public_accounts(website) if website else False
    }


def public_user_login(public_user):
    session['public_user_id'] = public_user.id
    session['public_user_website_id'] = public_user.website_id
    public_user.last_login_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()


def public_user_logout():
    session.pop('public_user_id', None)
    session.pop('public_user_website_id', None)


def get_request_ip():
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)

    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()

    return ip_address


def get_user_timezone(user=None):
    user = user or current_user

    timezone_name = getattr(user, 'timezone', None) or 'America/Chicago'

    try:
        return pytz.timezone(timezone_name)
    except Exception:
        return pytz.timezone('America/Chicago')


def format_user_datetime(value, user=None, fmt=None):
    if not value:
        return ''

    user = user or current_user
    user_timezone = get_user_timezone(user)

    fmt = fmt or getattr(user, 'date_format', None) or '%b %d, %Y %I:%M %p'

    # Your SQLite datetimes are naive, but stored as UTC.
    if value.tzinfo is None:
        value = pytz.utc.localize(value)

    local_value = value.astimezone(user_timezone)

    return local_value.strftime(fmt)

app.jinja_env.filters['user_datetime'] = format_user_datetime


def get_utc_start_for_user_local_days(days, user=None):
    user_timezone = get_user_timezone(user)

    local_today = datetime.now(user_timezone).date()

    local_start = user_timezone.localize(
        datetime.combine(
            local_today - timedelta(days=days - 1),
            datetime.min.time()
        )
    )

    return local_start.astimezone(pytz.utc).replace(tzinfo=None)


@app.cli.command("disable-2fa")
def disable_2fa_cli():
    """Emergency disable 2FA for the admin account."""
    user = User.query.first()

    if not user:
        print("No user found.")
        return

    disable_user_2fa(
        user,
        reason='an emergency server recovery command was used',
        needs_attention=True
    )

    db.session.commit()

    print(f"2FA disabled for {user.username}.")


@app.cli.command("reset-admin-password")
def reset_admin_password_cli():
    """Emergency reset the admin password from the server terminal."""
    import getpass

    user = User.query.first()

    if not user:
        print("No user found.")
        return

    print(f"Resetting password for admin user: {user.username}")
    new_password = getpass.getpass("New password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if not new_password:
        print("Password cannot be empty.")
        return

    if new_password != confirm_password:
        print("Passwords do not match.")
        return

    if len(new_password) < 10:
        print("Password should be at least 10 characters.")
        return

    user.set_password(new_password)

    # Optional but recommended for a true emergency reset:
    disable_user_2fa(
        user,
        reason='an emergency admin password recovery was performed',
        needs_attention=True
    )

    db.session.commit()

    print(f"Password reset successfully for {user.username}.")
    print("2FA was disabled. Log in, verify email settings, then re-enable 2FA.")


def load_emergency_login_tokens():
    if not os.path.exists(EMERGENCY_LOGIN_TOKENS_PATH):
        return []

    try:
        with open(EMERGENCY_LOGIN_TOKENS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_emergency_login_tokens(tokens):
    os.makedirs(os.path.dirname(EMERGENCY_LOGIN_TOKENS_PATH), exist_ok=True)

    with open(EMERGENCY_LOGIN_TOKENS_PATH, 'w', encoding='utf-8') as f:
        json.dump(tokens, f, indent=2)


def hash_emergency_login_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def cleanup_expired_emergency_login_tokens(tokens):
    now = int(time.time())

    return [
        token_record
        for token_record in tokens
        if int(token_record.get('expires_at', 0)) > now
    ]


def get_security_config():
    try:
        with open(SECURITY_CONFIG_PATH, 'r', encoding='utf-8') as f:
            loaded = json.load(f)

        config = DEFAULT_SECURITY_CONFIG.copy()
        config.update(loaded)
        return config

    except FileNotFoundError:
        return DEFAULT_SECURITY_CONFIG

    except Exception as e:
        print(f"Security config could not be loaded: {e}")
        return DEFAULT_SECURITY_CONFIG


def emergency_login_is_enabled():
    config = get_security_config()
    return bool(config.get("allow_emergency_login", False))


def get_emergency_login_expiration_seconds():
    config = get_security_config()

    try:
        minutes = int(config.get("emergency_login_expiration_minutes", 10))
    except (TypeError, ValueError):
        minutes = 10

    minutes = max(1, min(minutes, 60))

    return minutes * 60


@app.cli.command("emergency-login")
def emergency_login_cli():
    """Create a one-time emergency admin login link without changing password or 2FA."""
    if not emergency_login_is_enabled():
        print("Emergency login is disabled in config/security.json.")
        print("Set allow_emergency_login to true, then run this command again.")
        return
    user = User.query.first()

    if not user:
        print("No admin user found.")
        return

    confirm = input(
        "This creates a one-time admin login link that bypasses password and 2FA. Type EMERGENCY to continue: "
    ).strip()

    if confirm != "EMERGENCY":
        print("Emergency login cancelled.")
        return

    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_emergency_login_token(raw_token)

    now = int(time.time())
    expires_at = now + get_emergency_login_expiration_seconds()

    tokens = cleanup_expired_emergency_login_tokens(load_emergency_login_tokens())

    tokens.append({
        "token_hash": token_hash,
        "user_id": user.id,
        "created_at": now,
        "expires_at": expires_at,
        "used": False
    })

    save_emergency_login_tokens(tokens)

    path = f"/admin/emergency-login/{raw_token}"
    full_url = f"{get_emergency_login_base_url()}{path}"

    print("")
    print("========================================")
    print("UWEBIA EMERGENCY LOGIN LINK")
    print("This link is single-use.")
    print("")
    print(f"Path: {path}")
    print(f"URL:  {full_url}")
    print("========================================")
    print("")


def get_emergency_login_base_url():
    config = get_security_config()

    base_url = (config.get("emergency_login_base_url") or "").strip()

    if not base_url:
        return "http://127.0.0.1:5000"

    return base_url.rstrip("/")


@app.route('/admin/emergency-login/<token>')
def emergency_login(token):
    if not emergency_login_is_enabled():
        return "Emergency login is disabled.", 404
    token_hash = hash_emergency_login_token(token)

    tokens = cleanup_expired_emergency_login_tokens(load_emergency_login_tokens())

    matching_token = None

    for token_record in tokens:
        if (
                token_record.get('token_hash') == token_hash
                and not token_record.get('used')
        ):
            matching_token = token_record
            break

    if not matching_token:
        save_emergency_login_tokens(tokens)
        return "Emergency login link is invalid or expired.", 404

    user = User.query.get(matching_token.get('user_id'))

    if not user:
        return "Emergency login user not found.", 404

    # Mark token as used and save before logging in.
    matching_token['used'] = True
    matching_token['used_at'] = int(time.time())
    save_emergency_login_tokens(tokens)

    login_user(user)

    if admin_url_key_required_for_user(user):
        session['admin_path_verified'] = True

    _stamp_login(user)

    flash(
        'Emergency login successful.',
        'warning'
    )

    return redirect(url_for('dashboard'))


@app.cli.command("rebuild-forum-counts")
def rebuild_forum_counts():
    """Recalculate cached forum reply and vote counts."""
    print("Rebuilding forum counts...")

    threads = ForumThread.query.all()

    for thread in threads:
        visible_reply_count = ForumReply.query.filter_by(
            thread_id=thread.id,
            is_hidden=False
        ).count()

        thread_vote_count = ForumThreadVote.query.filter_by(
            thread_id=thread.id
        ).count()

        thread.reply_count = visible_reply_count
        thread.vote_count_cached = thread_vote_count

    replies = ForumReply.query.all()

    for reply in replies:
        reply_vote_count = ForumReplyVote.query.filter_by(
            reply_id=reply.id
        ).count()

        reply.vote_count_cached = reply_vote_count

    db.session.commit()

    print("Forum counts rebuilt successfully.")


@app.cli.command("audit-assets")
def audit_assets_cli():
    """Scan uploaded asset files for orphans and missing database files."""
    users = User.query.all()

    if not users:
        print("No users found.")
        return

    total_orphans = 0
    total_missing = 0
    total_orphan_bytes = 0

    for user in users:
        report = scan_user_asset_folder(user.id)

        total_orphans += len(report["orphan_files"])
        total_missing += len(report["missing_files"])
        total_orphan_bytes += report["orphan_bytes"]

        print("")
        print("========================================")
        print(f"User: {user.username} ({user.id})")
        print(f"Folder: {report['asset_folder']}")
        print(f"Database files: {report['referenced_count']}")
        print(f"Disk files: {report['actual_count']}")
        print(f"Orphan files: {len(report['orphan_files'])}")
        print(f"Missing files: {len(report['missing_files'])}")
        print(f"Orphan size: {format_bytes(report['orphan_bytes'])}")

        if report["orphan_files"]:
            print("")
            print("Orphans:")
            for filename in report["orphan_files"]:
                print(f"  - {filename}")

        if report["missing_files"]:
            print("")
            print("Missing database files:")
            for filename in report["missing_files"]:
                print(f"  - {filename}")

    print("")
    print("========================================")
    print("ASSET AUDIT SUMMARY")
    print(f"Total orphan files: {total_orphans}")
    print(f"Total missing files: {total_missing}")
    print(f"Total orphan size: {format_bytes(total_orphan_bytes)}")


def get_server_config():
    config = DEFAULT_SERVER_CONFIG.copy()

    try:
        with open(SERVER_CONFIG_PATH, 'r', encoding='utf-8') as f:
            loaded = json.load(f)

        if isinstance(loaded, dict):
            config.update(loaded)

    except FileNotFoundError:
        os.makedirs(os.path.dirname(SERVER_CONFIG_PATH), exist_ok=True)

        with open(SERVER_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)

    except json.JSONDecodeError as e:
        print(f"Invalid server config JSON. Using defaults. Error: {e}")

    host = str(config.get("host") or DEFAULT_SERVER_CONFIG["host"]).strip()

    try:
        port = int(config.get("port", DEFAULT_SERVER_CONFIG["port"]))
    except (TypeError, ValueError):
        port = DEFAULT_SERVER_CONFIG["port"]

    if port < 1 or port > 65535:
        port = DEFAULT_SERVER_CONFIG["port"]

    debug = bool(config.get("debug", DEFAULT_SERVER_CONFIG["debug"]))

    host = os.environ.get("HOST", host)

    try:
        port = int(os.environ.get("PORT", port))
    except (TypeError, ValueError):
        pass

    debug_env = os.environ.get("FLASK_DEBUG")
    if debug_env is not None:
        debug = debug_env.lower() in ("1", "true", "yes", "on")

    return {
        "host": host,
        "port": port,
        "debug": debug
    }

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


def ensure_default_website(user=None):
    """Create a default website (and home page) for a user if they don't have one.
    If no user is provided, operates on the first user in the database."""
    if user is None:
        user = User.query.first()
    if user is None:
        return
    # Sub-admins never get their own website — they share the parent's
    if user.parent_user_id:
        return
    if user.websites:
        return

    website = Website(name='My Website', user_id=user.id)
    db.session.add(website)
    db.session.flush()

    home_page = PublicPageContent(
        website_id=website.id,
        name='Home',
        slug='home',
        site_active_status=True,
        sort_order=0,
    )
    db.session.add(home_page)
    db.session.commit()
    print(f'Created default website and home page for user "{user.username}".')


def _run_startup_migrations():
    """Seamlessly upgrade an existing (or brand-new) database to match the
    current ORM models — no data loss, fully automatic.

    Strategy
    --------
    1. ``db.create_all()`` – creates every missing table from scratch.
    2. Auto-detect missing columns on pre-existing tables and add them with a
       safe DEFAULT so existing rows are not violated.
    3. Auto-detect missing indexes and create them.
    4. Never drop or rename columns/tables (those are destructive; handle
       manually if ever needed).

    All steps are idempotent: safe to run on every startup with multiple
    gunicorn workers.
    """
    from sqlalchemy import inspect as _inspect

    # ── Step 1: record which tables already exist, then create any missing ones
    inspector = _inspect(db.engine)
    pre_existing = set(inspector.get_table_names())
    db.create_all()
    # Re-inspect so newly created tables are in the picture
    inspector = _inspect(db.engine)

    # ── Step 2: add any columns that exist in the model but not in the DB ───
    for table in db.metadata.tables.values():
        tname = table.name

        # Tables that were just created by db.create_all() already have every
        # column; skip them to avoid noisy "already exists" attempts.
        if tname not in pre_existing:
            continue

        existing_col_names = {c['name'] for c in inspector.get_columns(tname)}

        for col in table.columns:
            if col.name in existing_col_names:
                continue

            # Compile the type string for this dialect (e.g. "VARCHAR(200)")
            try:
                col_type_str = col.type.compile(dialect=db.engine.dialect)
            except Exception:
                col_type_str = 'TEXT'

            # SQLite requires a DEFAULT when adding a NOT NULL column to an
            # existing table (otherwise the existing rows would violate it).
            default_clause = ''
            if col.server_default is not None:
                # e.g. server_default='0' or server_default=text("'chat'")
                raw = getattr(col.server_default, 'arg', str(col.server_default))
                default_clause = f' DEFAULT {raw}'
            elif col.default is not None and hasattr(col.default, 'arg'):
                arg = col.default.arg
                if not callable(arg):  # skip Python-side callables
                    default_clause = f' DEFAULT {arg!r}'
            elif not col.nullable:
                # Infer a zero-value default from the type so existing rows
                # satisfy the NOT NULL constraint without storing wrong data.
                t = col_type_str.upper()
                if any(k in t for k in ('INT', 'BOOL')):
                    default_clause = ' DEFAULT 0'
                elif any(k in t for k in ('REAL', 'FLOAT', 'NUMERIC', 'DECIMAL')):
                    default_clause = ' DEFAULT 0'
                elif 'JSON' in t:
                    default_clause = " DEFAULT '{}'"
                else:
                    default_clause = " DEFAULT ''"

            stmt = (f'ALTER TABLE "{tname}" '
                    f'ADD COLUMN "{col.name}" {col_type_str}{default_clause}')
            try:
                db.session.execute(db.text(stmt))
                db.session.commit()
                print(f'[migrate] + {tname}.{col.name} ({col_type_str})')
            except Exception as exc:
                db.session.rollback()
                msg = str(exc).lower()
                if 'duplicate column' not in msg and 'already exists' not in msg:
                    print(f'[migrate] warning: {tname}.{col.name}: {exc}')

    # ── Step 3: create any missing indexes ──────────────────────────────────
    for table in db.metadata.tables.values():
        if table.name not in pre_existing:
            continue
        try:
            existing_idx = {i['name'] for i in inspector.get_indexes(table.name)
                            if i.get('name')}
            for idx in table.indexes:
                if idx.name and idx.name not in existing_idx:
                    try:
                        idx.create(db.engine)
                        print(f'[migrate] + index {idx.name}')
                    except Exception as exc:
                        print(f'[migrate] warning: index {idx.name}: {exc}')
        except Exception:
            pass


# ── Startup initialisation ────────────────────────────────────────────────────
# Runs in every process that imports this module (each gunicorn worker as well
# as the master when --preload is used).  All operations must be idempotent.
with app.app_context():
    try:
        # Register the SQLite pragmas BEFORE the first connection so that even
        # db.create_all() benefits from busy_timeout and WAL mode.
        # Accessing db.engine inside the context is safe here.
        _sa_event.listens_for(db.engine, "connect")(_set_sqlite_pragmas)

        # Apply the pragmas immediately to any connection that may already be open
        # (unlikely at startup, but guards against edge cases).
        with db.engine.connect() as _conn:
            _conn.execute(db.text("PRAGMA journal_mode=WAL"))
            _conn.execute(db.text("PRAGMA synchronous=NORMAL"))
            _conn.execute(db.text("PRAGMA foreign_keys=ON"))
            _conn.execute(db.text("PRAGMA busy_timeout=5000"))

        # Create all tables from the ORM models (no-op if they already exist).
        # This is the call that generates site.db on a fresh install.
        _run_startup_migrations()

        ensure_default_website()

        # Start the background thread that periodically syncs external calendar
        # subscriptions. The daemon flag means it dies automatically when the
        # process exits. The module-level guard prevents double-start if the
        # Werkzeug reloader imports this module twice.
        import os as _os

        _reloader_parent = (
                _os.environ.get('WERKZEUG_RUN_MAIN') is None
                and _os.environ.get('FLASK_RUN_FROM_CLI') == 'true'
        )
        if not _reloader_parent:
            _start_subscription_sync_scheduler()

    except Exception as _startup_err:
        import traceback

        print("=" * 60)
        print("STARTUP ERROR — database initialisation failed:")
        traceback.print_exc()
        print("=" * 60)
        raise  # re-raise so gunicorn surfaces the failure rather than serving broken requests


@app.errorhandler(403)
def forbidden(e):
    msg = str(e.description) if hasattr(e, 'description') and e.description else \
        "You don't have permission to access this. Contact your admin."
    if request.is_json or request.headers.get('Accept', '').startswith('application/json'):
        return _utf8_json({'success': False, 'error': msg, 'permission_denied': True}, 403)
    return render_template('403.html', message=msg), 403


if __name__ == '__main__':
    server_config = get_server_config()

    app.run(
        debug=server_config["debug"],
        host=server_config["host"],
        port=server_config["port"]
    )
