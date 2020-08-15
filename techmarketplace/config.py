from flask import Flask
from techmarketplace.redisession import RedisSessionInterface
from datetime import timedelta
import redis
import os


def create_app():
    app = Flask(__name__)
    # app.session_interface = RedisSessionInterface()

    # general

    if os.environ.get('IS_PROD',None):
        app.config['SECRET_KEY'] = b'W\x1aa[\xaa(\x07X\xa3\x9a!A\x13YhJ\xa21\x1fh\x98\xfb\xb5\xc5\x96!\xa0y\x16\xf7\xe4\xb8'
        app.config['SECURITY_PASSWORD_SALT'] = b"\xe4\xa3@\x93\xed\x9aKb\xee\xa92'\x19\x16hJ"
    else:
        app.config['SECRET_KEY'] = os.urandom(32)
        app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16)
    app.config['UPLOAD_FOLDER'] = 'static\\upload'
    # email
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USERNAME'] = 'piethonlee123@gmail.com'
    app.config['MAIL_PASSWORD'] = 'dracula123456789'
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600
    # sqlalchemy
    if os.environ.get('IS_PROD',None):
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('CLEARDB_DATABASE_URL')
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format('dbmsuser','Henry123')  # get from key vault
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = True
    app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'
    # flask-session
    # app.config['SESSION_TYPE'] = 'redis'
    # app.config['SESSION_REDIS'] = redis.from_url('redis://:RZ9IoOQMPab4XGaLee7NUAW6vccBceAU@redis-12106.c56.east-us.azure.cloud.redislabs.com:12106/0')
    #cors
    app.config['CORS_HEADERS'] = 'Content-Type'

    return app