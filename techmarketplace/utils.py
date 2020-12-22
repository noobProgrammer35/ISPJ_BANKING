from hashlib import pbkdf2_hmac
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask_mail import Message,Mail
from math import radians, cos, sin, asin, sqrt
from twilio.rest import Client, TwilioException
from zipfile import ZipFile
import os
import requests
import re
import socket
import subprocess
import datetime

if not os.environ.get('IS_PROD',None):
    from techmarketplace import Configuration



def generate_salt(): # salt is IV in hashing, this function generates random 16 bits in hexadecimal
    salt =  os.urandom(16)
    return salt.hex()


def generate_hash(plaintext_password,password_salt):
    print('')
    password_hash = pbkdf2_hmac(
        'sha256',
        b"%b"  % bytes(plaintext_password,'utf-8'),
        b"%b" % bytes(password_salt,'utf-8'),
        10000
    )
    return password_hash.hex()


def generate_token(email):
    # serialize and sign the data
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email,current_app.config['SECURITY_PASSWORD_SALT'])


def confirmation_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age = expiration
        )
    except:
        return False
    return email



def send_email(to,subject,template):
    mail = Mail(current_app)
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender = 'piethonlee123@gmail.com'
    )
    mail.send(msg)

def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    r = 6371 # Radius of earth in kilometers. Use 3956 for miles
    return c * r

center_point = [{'lat':1.3796268,'lng':103.8474183}]
test_point = [{'lat':1.3364408,'lng':103.8449139}]
lat1 = center_point[0]['lat']
lon1 = center_point[0]['lng']
lat2 = test_point[0]['lat']
lon2 = test_point[0]['lng']

radius = 0.2

a = haversine(lon1, lat1, lon2, lat2)


print('Distance (km) : ', a)
if a <= radius:
    print('Inside the area')
else:
    print('Outside the area')


def get_location():
    res = requests.get('http://ipinfo.io/')
    data = res.json()
    print(res.text)
    return data['loc'].split(',')

def get_ipaddress():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg','gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def banned_characters(field,matches="[/\'\"#<>%\\\]"):
    print(field)
    return re.search(matches,str(field))

def read_common_password(field):
    dict = {}
    with open('10k-most-common.txt', 'r') as file:
        data = file.readlines()
        for counter, data in enumerate(data):
            dict[data.strip()] = counter

    if str(field.lower()) in dict:
        return True

def mailgun_send_message(to,subject,html):
    domain = os.environ.get('MAILGUN_DOMAIN',None)
    url = 'https://api.mailgun.net/v3/{0}/messages'.format(domain)
    data = 'mailgun@{0}'.format(domain)
    API = os.environ.get('MAILGUN_API_KEY',None)
    return requests.post(
        url,
        auth=("api", API),
        data={"from": data,
              "to": to,
              "subject": subject,
              "html":html})

def mailgun_send_messageV2(to,subject,html,sender):
    domain = os.environ.get('MAILGUN_DOMAIN',None)
    url = 'https://api.mailgun.net/v3/{0}/messages'.format(domain)
    data = 'mailgun@{0}'.format(domain)
    API = os.environ.get('MAILGUN_API_KEY',None)
    return requests.post(
        url,
        auth=("api", API),
        data={"from": sender,
              "to": to,
              "subject": subject,
              "text":html})


def request_twilio_token(phone):
    if os.environ.get('IS_PROD',None):
        verify = Client(os.environ.get('twilioSID',None),os.environ.get('TwilioAuthToken',None)).verify.services(os.environ.get('TwilioServiceID'))
    else:
        verify =  Client(Configuration.accountSID,Configuration.auth_token).verify.services(Configuration.serviceSID)
    verify.verifications.create(to='+65'+phone,channel='sms')


def verify_twilio_token(phone,token):
    if os.environ.get('IS_PROD', None):
        verify = Client(os.environ.get('twilioSID', None), os.environ.get('TwilioAuthToken', None)).verify.services(
            os.environ.get('TwilioServiceID'))
    else:
        verify = Client(Configuration.accountSID, Configuration.auth_token).verify.services(Configuration.serviceSID)
    try:
        result = verify.verification_checks.create(to='+65'+phone,code=token)
    except TwilioException:
        return False
    return result.status == 'approved'


def check_exist(path):
    if os.path.exists(path):
        return True
    else:
        os.mkdir("D:/ManualBackup_Database")


def database_backup(option):
    default_path = "D:\\ManualBackup_Database\\"
    date = datetime.datetime.today().now()
    default_filename = "db_backup_"+datetime.datetime.strftime(date,'%Y%m%d')+".sql"
    check_exist(default_path)
    if not os.path.exists('D:/Manualbackup_Database/%s' % option):
        os.mkdir('D:/Manualbackup_Database/%s' % option)
    store = default_path + option + "/"
    if option == 'Full_Record':
        command = 'mysqldump -uroot -pHenry123 -hlocalhost mydb -r %s'%(store+default_filename)
        os.chdir('C:/Program Files/MySQL/MySQL Workbench 8.0 CE')
        subprocess.call(command)
    else:
        command = 'mysqldump -uroot -pHenry123 -hlocalhost mydb %s -r %s'%(option,store+default_filename)
        os.chdir("C:/Program Files/MySQL/MySQL Workbench 8.0 CE")
        subprocess.call(command)