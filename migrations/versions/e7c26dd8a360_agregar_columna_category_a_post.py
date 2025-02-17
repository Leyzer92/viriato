"""Agregar columna category a Post

Revision ID: e7c26dd8a360
Revises: 38ed37318267
Create Date: 2025-02-16 15:03:02.088495

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e7c26dd8a360'
down_revision = '38ed37318267'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.add_column(sa.Column('category', sa.String(length=50), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_column('category')

    # ### end Alembic commands ###
