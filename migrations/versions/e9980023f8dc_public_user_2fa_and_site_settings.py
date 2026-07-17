"""public_user_2fa_and_site_settings

Revision ID: e9980023f8dc
Revises:
Create Date: 2026-05-14 20:36:56.895329

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e9980023f8dc'
down_revision = None
branch_labels = None
depends_on = None


def _add_column_if_missing(table, column_def):
    """ADD COLUMN ... IF NOT EXISTS — safe to run on databases that already
    have the column as well as those that don't."""
    op.execute(
        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column_def}"
    )


def upgrade():
    # ── New columns added in this branch ──────────────────────────────────────
    _add_column_if_missing('public_user',
                           'two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE')
    _add_column_if_missing('public_user',
                           'two_factor_last_sent_at TIMESTAMP')
    _add_column_if_missing('website',
                           'public_users_enabled BOOLEAN NOT NULL DEFAULT TRUE')
    _add_column_if_missing('website',
                           'public_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE')

    # ── Columns that may have been added as nullable in earlier deployments ───
    # ALTER COLUMN ... SET NOT NULL is a no-op when already NOT NULL, so these
    # are safe to run against both old and up-to-date databases.
    with op.batch_alter_table('calendar_event', schema=None) as batch_op:
        batch_op.alter_column('all_day',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('hide_time',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))

    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.alter_column('comments_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('comments_require_login',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('comments_moderation',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))

    with op.batch_alter_table('post_comment', schema=None) as batch_op:
        batch_op.alter_column('like_count_cached',
               existing_type=sa.INTEGER(),
               nullable=False,
               existing_server_default=sa.text('0'))

    with op.batch_alter_table('website', schema=None) as batch_op:
        batch_op.alter_column('is_live',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('true'))
        batch_op.alter_column('store_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('true'))
        batch_op.alter_column('store_in_store_only',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('store_title',
               existing_type=sa.VARCHAR(length=120),
               nullable=False,
               existing_server_default=sa.text("'Shop'::character varying"))
        batch_op.alter_column('post_profanity_action',
               existing_type=sa.VARCHAR(length=10),
               nullable=False,
               existing_server_default=sa.text("'block'::character varying"))
        batch_op.alter_column('profanity_filter_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('reviews_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('require_login_to_view',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('public_approval_required',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('public_email_verification_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('public_email_verification_required',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))
        batch_op.alter_column('public_users_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('true'))
        batch_op.alter_column('public_2fa_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))

    with op.batch_alter_table('public_user', schema=None) as batch_op:
        batch_op.alter_column('two_factor_enabled',
               existing_type=sa.BOOLEAN(),
               nullable=False,
               existing_server_default=sa.text('false'))


def downgrade():
    pass
