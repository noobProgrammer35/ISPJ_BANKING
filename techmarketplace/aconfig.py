from flask import Flask
from techmarketplace.redisession import RedisSessionInterface
from techmarketplace import  Configuration
from datetime import timedelta
import redis
import os


def create_app():
    app = Flask(__name__,template_folder='backend')
    app.session_interface = RedisSessionInterface()

    # general
    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16)
    app.config['UPLOAD_FOLDER'] = 'static\\upload'

    # sqlalchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://{0}:{1}@localhost/mydb'.format(Configuration.dbuser,Configuration.dbpw)  # get from key vault
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = True
    app.config['MYSQL_DATABASE_CHARSET'] = 'utf8mb4'
    # flask-session
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url('redis://:qaLCHO8v04Q9bn7dVWOAjfZjy98RrxD1@redis-12772.c56.east-us.azure.cloud.redislabs.com:12772/0')
    return app