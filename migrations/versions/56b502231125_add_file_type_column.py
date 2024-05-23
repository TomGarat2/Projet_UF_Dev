"""Add file_type column

Revision ID: 56b502231125
Revises: 
Create Date: 2024-05-21 14:50:36.033908

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '56b502231125'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('file', schema=None) as batch_op:
        batch_op.add_column(sa.Column('file_type', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('file_size', sa.Integer(), nullable=True))
        batch_op.drop_column('path')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('file', schema=None) as batch_op:
        batch_op.add_column(sa.Column('path', sa.VARCHAR(length=200), nullable=False))
        batch_op.drop_column('file_size')
        batch_op.drop_column('file_type')

    # ### end Alembic commands ###