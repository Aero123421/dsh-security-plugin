from flask import Flask
from .admin import admin_bp
from .api import api_bp

app = Flask(__name__)
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(api_bp)


@app.route('/')
def index():
    return 'home'


@app.route('/login', methods=['GET', 'POST'])
def login():
    return 'login'
