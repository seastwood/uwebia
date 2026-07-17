#!/usr/bin/env python3
"""
Migration: create the review_board and review tables for the Reviews asset.

Run from the project root:
    python migrations/add_reviews.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import inspect as sa_inspect


def migrate():
    with app.app_context():
        insp = sa_inspect(db.engine)
        existing = set(insp.get_table_names())
        created = []
        # create_all only creates tables that don't yet exist, so this is safe
        # to run repeatedly.
        db.create_all()
        for tbl in ('review_board', 'review'):
            if tbl not in existing:
                created.append(tbl)
        if created:
            print('Created tables: ' + ', '.join(created))
        else:
            print('Tables review_board and review already exist')


if __name__ == '__main__':
    migrate()
