from flask import Blueprint

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')


@api_bp.route('/items/<item_id>', methods=['DELETE'])
def delete_item(item_id):
    return '', 204
