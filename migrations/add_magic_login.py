#!/usr/bin/env python3
"""
Migration: passwordless email sign-in ("magic link").

Adds two nullable columns to `public_user` AND `user` (admins can use magic
links on the public site too — the link stands in for a correct password, and
2FA-protected admins still go through the code step):
  - login_link_nonce    VARCHAR(64) — random per-link nonce; embedded in the
                        signed token and cleared on use, making every link
                        single-use (and a newer link invalidates older ones).
  - login_link_sent_at  DATETIME    — last time a link was emailed; drives the
                        one-per-minute resend cooldown.

Idempotent. Run from the project root:
    python migrations/add_magic_login.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db
from sqlalchemy import text, inspect as sa_inspect


def migrate():
    with app.app_context():
        insp = sa_inspect(db.engine)
        dialect = db.engine.dialect.name
        dt_type = 'TIMESTAMP' if dialect in ('postgresql', 'postgres') else 'DATETIME'

        to_add = {
            'login_link_nonce': 'VARCHAR(64)',
            'login_link_sent_at': dt_type,
        }

        with db.engine.connect() as conn:
            for tname in ('public_user', 'user'):
                cols = {c['name'] for c in insp.get_columns(tname)}
                for name, coltype in to_add.items():
                    if name in cols:
                        print(f'Column {tname}.{name} already exists')
                        continue
                    conn.execute(text(f'ALTER TABLE "{tname}" ADD COLUMN {name} {coltype}'))
                    conn.commit()
                    print(f'Added column {tname}.{name}')

        print('Done.')


if __name__ == '__main__':
    migrate()
