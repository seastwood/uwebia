#!/usr/bin/env python3
"""
Migration: add website_permissions JSON column to the user table.

Run from the project root:
    python migrations/add_website_permissions.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text, inspect as sa_inspect


def migrate():
    with app.app_context():
        insp = sa_inspect(db.engine)
        cols = [c['name'] for c in insp.get_columns('user')]
        if 'website_permissions' not in cols:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE \"user\" ADD COLUMN website_permissions JSON"))
                conn.commit()
            print('Added column user.website_permissions')
        else:
            print('Column user.website_permissions already exists')


if __name__ == '__main__':
    migrate()
