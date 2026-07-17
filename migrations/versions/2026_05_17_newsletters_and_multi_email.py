"""newsletters_and_multi_email

Revision ID: a1b2c3d4e5f6
Revises: e9980023f8dc
Create Date: 2026-05-17 12:00:00.000000

Adds Newsletter / NewsletterSubscriber / NewsletterCampaign tables and
extends email_server_settings with label + is_default so multiple servers
can be configured.

"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = 'e9980023f8dc'
branch_labels = None
depends_on = None


def _add_column_if_missing(table, column_def):
    op.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column_def}")


def upgrade():
    # ── email_server_settings: multi-server support ──────────────────────────
    _add_column_if_missing('email_server_settings',
                           "label VARCHAR(200) NOT NULL DEFAULT 'Default'")
    _add_column_if_missing('email_server_settings',
                           'is_default BOOLEAN NOT NULL DEFAULT FALSE')

    # Promote the existing single row to default when nothing is flagged yet.
    op.execute("""
        UPDATE email_server_settings
           SET is_default = TRUE
         WHERE id = (SELECT id FROM email_server_settings ORDER BY id LIMIT 1)
           AND NOT EXISTS (SELECT 1 FROM email_server_settings WHERE is_default = TRUE)
    """)

    # ── newsletter ───────────────────────────────────────────────────────────
    op.create_table(
        'newsletter',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True, index=True),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('slug', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cover_image_url', sa.String(length=500), nullable=True),
        sa.Column('signup_button_label', sa.String(length=80), nullable=False, server_default='Subscribe'),
        sa.Column('signup_heading', sa.String(length=200), nullable=False, server_default='Subscribe to our newsletter'),
        sa.Column('signup_blurb', sa.Text(), nullable=True),
        sa.Column('signup_success_message', sa.Text(), nullable=False,
                  server_default='Check your inbox for a confirmation email.'),
        sa.Column('confirmation_subject', sa.String(length=200), nullable=False,
                  server_default='Please confirm your subscription'),
        sa.Column('confirmation_intro', sa.Text(), nullable=True),
        sa.Column('default_subject_prefix', sa.String(length=120), nullable=True),
        sa.Column('email_server_id', sa.Integer(),
                  sa.ForeignKey('email_server_settings.id', ondelete='SET NULL'),
                  nullable=True),
        sa.Column('require_double_optin', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('collect_name', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('user_id', 'slug', name='uq_newsletter_user_slug'),
    )

    # ── newsletter_subscriber ────────────────────────────────────────────────
    op.create_table(
        'newsletter_subscriber',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('newsletter_id', sa.Integer(),
                  sa.ForeignKey('newsletter.id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('email', sa.String(length=255), nullable=False, index=True),
        sa.Column('name', sa.String(length=200), nullable=True),
        sa.Column('subscribed_at', sa.DateTime(), nullable=True),
        sa.Column('confirmed_at', sa.DateTime(), nullable=True),
        sa.Column('unsubscribed_at', sa.DateTime(), nullable=True),
        sa.Column('confirmation_token', sa.String(length=64), nullable=True, index=True),
        sa.Column('unsubscribe_token', sa.String(length=64), nullable=False, index=True),
        sa.Column('source', sa.String(length=120), nullable=True),
        sa.Column('last_emailed_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('newsletter_id', 'email', name='uq_newsletter_subscriber_email'),
    )

    # ── newsletter_campaign ──────────────────────────────────────────────────
    op.create_table(
        'newsletter_campaign',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('newsletter_id', sa.Integer(),
                  sa.ForeignKey('newsletter.id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('subject', sa.String(length=300), nullable=False),
        sa.Column('html_body', sa.Text(), nullable=False, server_default=''),
        sa.Column('plain_body', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='draft'),
        sa.Column('email_server_id', sa.Integer(),
                  sa.ForeignKey('email_server_settings.id', ondelete='SET NULL'),
                  nullable=True),
        sa.Column('recipient_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('success_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('fail_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table('newsletter_campaign')
    op.drop_table('newsletter_subscriber')
    op.drop_table('newsletter')
    with op.batch_alter_table('email_server_settings') as batch_op:
        batch_op.drop_column('is_default')
        batch_op.drop_column('label')
