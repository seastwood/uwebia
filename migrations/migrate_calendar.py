#!/usr/bin/env python3
"""
One-time migration: move from section-based calendars to the new Calendar model.

Run from the project root:
    python migrations/migrate_calendar.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app, db, Calendar, CalendarEvent, CalendarFeedSubscriber, PageSection, PublicPageContent
from sqlalchemy import text, inspect as sa_inspect


def add_column_if_missing(conn, table, column, definition):
    insp = sa_inspect(db.engine)
    cols = [c['name'] for c in insp.get_columns(table)]
    if column not in cols:
        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {definition}'))
        conn.commit()
        print(f'  Added column {table}.{column}')
    else:
        print(f'  Column {table}.{column} already exists')


def migrate():
    with app.app_context():
        # 1. Create new tables (Calendar) if they don't exist yet
        db.create_all()
        print('Tables created / verified.')

        # 2. Add calendar_id columns to existing tables if missing
        with db.engine.connect() as conn:
            add_column_if_missing(conn, 'calendar_event', 'calendar_id', 'INTEGER REFERENCES calendar(id)')
            add_column_if_missing(conn, 'calendar_feed_subscriber', 'calendar_id', 'INTEGER REFERENCES calendar(id)')

        # 3. Migrate existing calendar sections
        calendar_sections = PageSection.query.filter_by(section_type='calendar').all()
        print(f'\nFound {len(calendar_sections)} calendar section(s) to migrate.')

        migrated = 0
        for section in calendar_sections:
            # Skip if already migrated
            content = section.content or {}
            if content.get('calendar_id'):
                print(f'  Section {section.id}: already migrated (calendar_id={content["calendar_id"]}), skipping.')
                continue

            page = PublicPageContent.query.get(section.page_content_id)
            if not page:
                print(f'  Section {section.id}: orphaned (no page), skipping.')
                continue

            # Create a Calendar record for this section
            cal_name = f'{page.name} Calendar'
            cal = Calendar(name=cal_name, website_id=page.website_id)
            db.session.add(cal)
            db.session.flush()

            # Migrate events
            events = CalendarEvent.query.filter_by(section_id=section.id).all()
            for event in events:
                event.calendar_id = cal.id

            # Migrate subscribers
            subs = CalendarFeedSubscriber.query.filter_by(section_id=section.id).all()
            for sub in subs:
                sub.calendar_id = cal.id

            # Update section content to reference the new calendar
            new_content = dict(content)
            new_content['calendar_id'] = cal.id
            section.content = new_content

            db.session.commit()
            print(f'  Section {section.id} → Calendar "{cal_name}" (id={cal.id}), '
                  f'{len(events)} event(s), {len(subs)} subscriber(s) migrated.')
            migrated += 1

        print(f'\nMigration complete. {migrated} section(s) migrated.')


if __name__ == '__main__':
    migrate()
