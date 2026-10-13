from flask import Blueprint
from flask_login import login_required

admin_bp = Blueprint('admin', __name__, url_prefix='/ignored')


@admin_bp.get('/users/<int:user_id>')
@login_required
def show_user(user_id):
    return str(user_id)


@admin_bp.post('/reports')
@jwt_required()
@roles_required('admin')
def create_report():
    return 'ok'
