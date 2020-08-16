from flask import Flask
from techmarketplace import vault
import os


def create_app():
    v = vault.Vault()

    app = Flask(__name__)
    # app.session_interface = RedisSessionInterface()

    # general

    if os.environ.get('IS_PROD',None):
        secret_key = v.get_secret('SECRET-KEY')
        security_password_salt  = v.get_secret(('security-password-salt'))
        app.config['SECRET_KEY'] = secret_key
        app.config['SECURITY_PASSWORD_SALT'] = security_password_salt
    else:
        app.config['SECRET_KEY'] = os.urandom(32)
        app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16)
    app.config['UPLOAD_FOLDER'] = 'static\\upload'
    # email
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600
    # sqlalchemy
    if os.environ.get('IS_PROD',None):
        app.config['SQLALCHEMY_DATABASE_URI'] = v.get_secret('DatabaseConnectionString')
    else:
        from techmarketplace import Configuration
        app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format(Configuration.dbuser,Configuration.dbpw)  # get from key vault
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = True
    app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'

    #cors
    app.config['CORS_HEADERS'] = 'Content-Type'

    v.close_all_connections()
    return app