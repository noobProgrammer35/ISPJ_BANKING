from flask import Flask
from techmarketplace import vault
import os


def create_app():
    v = vault.Vault()

    app = Flask(__name__)
    # app.session_interface = RedisSessionInterface()

    # general

    if os.environ.get('IS_PROD',None):
        secret_key =  os.urandom(32)     #v.get_secret('SECRET-KEY')
        security_password_salt  =  os.urandom(16)   #v.get_secret(('security-password-salt'))
        app.config['SECRET_KEY'] = secret_key
        app.config['SECURITY_PASSWORD_SALT'] = security_password_salt
    else:
        app.config['SECRET_KEY'] = os.urandom(32)
        app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16)
    app.config['UPLOAD_FOLDER'] = 'static\\upload'
    # email
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'pycharming123@gmail.com'
    app.config['MAIL_PASSWORD'] = '123' #v.get_secret()
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600
    # sqlalchemy
    if os.environ.get('IS_PROD',None):
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('CLEARDB_DATABASE_URL') #v.get_secret('DatabaseConnectionString')
    else:
        from techmarketplace import Configuration
        app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format(Configuration.dbuser,Configuration.dbpw)  # get from key vault
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = True
    app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'

    #cors
    app.config['CORS_HEADERS'] = 'Content-Type'

    #recaptcha
    if os.environ.get('IS_PROD',None):
        app.config['RECAPTCHA_USE_SSL'] = False
        app.config['RECAPTCHA_ENABLED'] = True
        #app.config['RECAPTCHA_PUBLIC_KEY'] = v.get_secret('RECAPTCHA-PUBLIC-KEY')
        #app.config['RECAPTCHA_PRIVATE_KEY'] = v.get_secret('RECAPTCHA-PRIVATE-KEY')
        app.config['RECAPTCHA_OPTIONS'] = {'theme': 'black'}

    v.close_all_connections()
    return app