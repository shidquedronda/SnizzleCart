from flask import Flask
from flask_login import LoginManager
from utils.user_loader import load_user
import os

app = Flask(__name__)
app.secret_key = 'pokimon12'
app.config['UPLOAD_FOLDER_PRODUCTS'] = os.path.join(app.static_folder, 'images')
app.config['UPLOAD_FOLDER_PROFILE'] = os.path.join(app.static_folder, 'profile_img')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.user_loader(load_user)

from controllers.auth_controller import *
from controllers.product_controller import *
from controllers.profile_controller import *
from controllers.cart_controller import *
from controllers.misc_controller import *

if __name__ == '__main__':
    app.run(debug=True)
