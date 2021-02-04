from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from hashlib import pbkdf2_hmac
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin,AdminIndexView,expose
from flask_login import LoginManager,current_user, UserMixin,login_user,AnonymousUserMixin
import os


database = SQLAlchemy(current_app)
login = LoginManager(current_app)
login.login_view = '/login'
login.session_protection = None
login.refresh_view = '/login'
login.needs_refresh_message = (u"Session timedout, please re-login")
login.needs_refresh_message_category = "info"

@login.user_loader
def get_id(userid):
    return Customer.query.get(int(userid))

passbook_user = database.Table('passbook_user',database.Column('passbookid',database.Integer,database.ForeignKey('passbook.passbookid'),primary_key=True),database.Column('userid',database.Integer(),database.ForeignKey('users.userid'),primary_key=True))

class passbook_users(database.Model):
    __tablename__ = 'passbook_user'
    __table_args__ = {'extend_existing': True}
    passbookid = database.Column(database.Integer,database.ForeignKey('passbook.passbookid'),primary_key=True)
    userid = database.Column(database.Integer,database.ForeignKey('users.userid'),primary_key=True)

    def __init__(self,passbookid,userid):
        self.passbookid = passbookid
        self.userid = userid

    def __repr__(self):
        return "<passbook_user %r>" % self.passbookid

class Customer(database.Model, UserMixin):
    __tablename__ = 'users'
    userid = database.Column(database.Integer,primary_key=True)
    username = database.Column(database.String(50), unique=True)
    fname = database.Column(database.String(45))
    lname = database.Column(database.String(45))
    contact = database.Column(database.String(20))
    email = database.Column(database.String(45),unique=True)
    password_hash = database.Column(database.Text())
    password_salt = database.Column(database.Text())
    verified = database.Column(database.Boolean)
    failed_attempt = database.Column(database.Integer())
    failed_login_time = database.Column(database.TIMESTAMP())
    balance = database.Column(database.Numeric(6,2))
    account = database.relationship('Account',uselist=False,backref='account',lazy=True)
    passbookuser = database.relationship('passbook',secondary=passbook_user,backref=database.backref('users',lazy='joined'))

    def __init__(self,username,fname,lname,contact,password,verified,email):
        self.username = username
        self.fname = fname
        self.lname = lname
        self.contact = contact
        self.email = email
        self.verified = verified
        self.password_salt = self.generate_salt()
        self.password_hash = self.generate_hash(password,self.password_salt)
        self.failed_attempt = 0

    def generate_hash(self,plaintext_password,salt):
        password_hash = pbkdf2_hmac(
            'sha256',
            b"%b" % bytes(plaintext_password, 'utf-8'),
            b"%b" % bytes(salt, 'utf-8'),
            10000
        )
        return password_hash.hex()

    def generate_salt(self):
        salt = os.urandom(16)
        return salt.hex()

    def get_id(self):
        return self.userid



class Account(database.Model):
    __tablename__ = 'account'
    accountid = database.Column(database.Integer,primary_key=True,unique=True)
    address = database.Column(database.String(55),nullable=False)
    credit_card = database.Column(database.LargeBinary,nullable=False)
    payment_method = database.Column(database.String(20))
    userid = database.Column(database.Integer,database.ForeignKey('users.userid'))

    def __init__(self,userid):
        self.address = ''
        self.payment_method = 'Credit Card'
        self.userid = userid

class KVSession(database.Model):
    __tablename__ = 'session'
    key = database.Column(database.String(100),primary_key=True,unique=True)
    value = database.Column(database.LargeBinary())

    def __repr__(self):
        return "<Session %r>" % self.key



class passbook(database.Model):
    __tablename__ = 'passbook'
    passbookid = database.Column(database.Integer,primary_key=True,unique=True)
    date = database.Column(database.DateTime())
    details = database.Column(database.String(100))
    amount = database.Column(database.Numeric())
    new_balance = database.Column(database.Numeric())

    def __init__(self,date,details,amount,new_balance):
        self.date = date
        self.details = details
        self.amount = amount
        self.new_balance = new_balance

    def __repr__(self):
        return "<Passbook %r>" % self.passbookid

# need to del
# class Product(UserMixin,database.Model):
#     __tablename__ = 'products'
#     productid = database.Column(database.Integer,primary_key=True)
#     Name = database.Column(database.String(45))
#     Description = database.Column(database.String(100))
#     stock = database.Column(database.Integer)
#     price = database.Column(database.Float(2,6))
#     Image = database.Column(database.String)
#     Image2 = database.Column(database.String)
#     model = database.Column(database.String,unique=True)
#
#     def __init__(self,productName,productDescription,stock,price,imageFileName,Image2,model):
#         self.Name = productName
#         self.Description = productDescription
#         self.stock = stock
#         self.price = price
#         self.Image =imageFileName
#         self.Image2 = Image2
#         self.model = model
#
#     def get_id(self):
#         return self.productid
#
#     def __repr__(self):
#         return "<Product %r>" % self.productid