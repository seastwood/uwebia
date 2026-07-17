#!/usr/bin/env python3
"""
Migration: enforce globally-unique public-user login usernames.

Until now `public_user.username` was only unique *per website*
(`uq_public_user_username_per_website`), so the same username could be claimed
on two different sites. This migration makes real public usernames unique
across every website (groundwork for cross-website accounts) by adding a
partial unique index on `username` WHERE `mirrored_admin_user_id IS NULL`.

Admin mirrors are exempt: they all represent the same global admin and repeat
on every site by design, so they are not covered by the index.

Existing cross-site duplicates are auto-resolved before the index is created:
the oldest account keeps the name and the rest are suffixed (`bob` -> `bob-2`,
`bob-3`, ...), skipping any suffix that is itself taken. Email is left alone.

Idempotent. Run from the project root:
    python migrations/add_global_public_username.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db, PublicUser, User
from sqlalchemy import inspect as sa_inspect


INDEX_NAME = 'uq_public_user_username_global'


def _name_is_free(name, keep_id):
    """True if `name` is unused by any admin or any real public user other than
    `keep_id` (the row we're about to assign it to)."""
    if User.query.filter(User.username == name).first():
        return False
    clash = PublicUser.query.filter(
        PublicUser.username == name,
        PublicUser.mirrored_admin_user_id.is_(None),
        PublicUser.id != keep_id,
    ).first()
    return clash is None


def _resolve_duplicates():
    """Rename real public users so each login username is globally unique.
    Keeps the oldest row per name (created_at, then id) and suffixes the rest."""
    reals = (
        PublicUser.query
        .filter(PublicUser.mirrored_admin_user_id.is_(None))
        .all()
    )

    by_name = {}
    for pu in reals:
        by_name.setdefault((pu.username or '').strip().lower(), []).append(pu)

    renamed = 0
    for name, rows in by_name.items():
        if not name or len(rows) < 2:
            continue
        # Stable order: oldest first keeps the original name.
        rows.sort(key=lambda r: (r.created_at or __import__('datetime').datetime.min, r.id))
        for pu in rows[1:]:
            n = 2
            while True:
                candidate = f'{name}-{n}'
                if _name_is_free(candidate, pu.id):
                    break
                n += 1
            print(f'  Renaming public_user id={pu.id} (website {pu.website_id}): '
                  f'{pu.username!r} -> {candidate!r}')
            pu.username = candidate
            renamed += 1

    if renamed:
        db.session.commit()
        print(f'  Resolved {renamed} duplicate username(s).')
    else:
        print('  No cross-site duplicate usernames found.')


def _index_exists():
    insp = sa_inspect(db.engine)
    names = {ix['name'] for ix in insp.get_indexes('public_user')}
    return INDEX_NAME in names


def _create_index():
    if _index_exists():
        print(f'Index {INDEX_NAME} already exists')
        return
    dialect = db.engine.dialect.name
    if dialect == 'sqlite':
        sql = (f'CREATE UNIQUE INDEX {INDEX_NAME} ON public_user (username) '
               'WHERE mirrored_admin_user_id IS NULL')
    elif dialect in ('postgresql', 'postgres'):
        sql = (f'CREATE UNIQUE INDEX {INDEX_NAME} ON public_user (username) '
               'WHERE mirrored_admin_user_id IS NULL')
    else:
        raise RuntimeError(f'Unsupported dialect for partial index: {dialect}')
    from sqlalchemy import text
    with db.engine.begin() as conn:
        conn.execute(text(sql))
    print(f'Created partial unique index {INDEX_NAME}')


def migrate():
    with app.app_context():
        insp = sa_inspect(db.engine)
        cols = {c['name'] for c in insp.get_columns('public_user')}
        if 'mirrored_admin_user_id' not in cols:
            print('ERROR: public_user.mirrored_admin_user_id is missing. Run the '
                  'admin-mirror migration first, then re-run this script.')
            sys.exit(1)

        print('Resolving any cross-site duplicate public usernames...')
        _resolve_duplicates()
        _create_index()
        print('Done.')


if __name__ == '__main__':
    migrate()
