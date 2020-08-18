from flask import jsonify,request,flash,Flask,render_template,redirect,session,url_for,Response,abort,json,escape,g,make_response
from flask_wtf.csrf import CSRFProtect,CSRFError
from flask_sqlalchemy import *
from techmarketplace.Form import RegisterForm, LoginForm,AccountForm,EmailForm,SearchForm,SupportForm,ChangePasswordForm
from techmarketplace import utils,config,redisession
from flask_login import current_user,logout_user
from flask_paranoid import Paranoid
from flask_talisman import Talisman
from opencensus.ext.azure import metrics_exporter
from flask_cors import CORS,cross_origin
import datetime
from functools import wraps
from werkzeug.datastructures import Headers
import socket
from sqlalchemy import or_,and_
import requests
import psutil
from uuid import uuid4
import redis
import pickle
import time



app = config.create_app()
# exporter = metrics_exporter.new_metrics_exporter(connection_string='InstrumentationKey=bec9fb90-0c7a-417a-809e-6c5417e4ba98')
with app.app_context():
    from techmarketplace.api.routes import userAPI
    from techmarketplace import Models,vault,log,test
    app.register_blueprint(userAPI.users_blueprint)
    Models.database.create_all()
    # a = Models.Admin.query.get(1)
    # try:
    #     x = Models.Admin('Henry123','password123',96279135,'superuser')
    #     Models.database.session.add(x)
    #     Models.database.session.commit()
    # except:
    #     Models.database.session.rollback()
    # print(Models.roles.query.filter_by(type='admin').first())
    # s = Models.Admin.query.filter_by(username='Henry223').first()
    # print(a.adminid)

# xss and data injection
csp = {
        'default-src': ['\'self\'','https://fonts.googleapis.com/css'],
        'img-src': ['\'self\' data:','www.gstatic.com'],
        'style-src': '\'unsafe-inline\' \'self\'',
        'script-src': ['\'unsafe-inline\' \'self\'',' https://www.google.com/recaptcha/api.js',' https://www.gstatic.com/recaptcha/releases/TPiWapjoyMdQOtxLT9_b4n2W/recaptcha__en.js','nonce-{NONCE}'],
        'frame-src':['www.google.com']

}

csrf = CSRFProtect(app)
#session protection
paranoid = Paranoid(app)
talisman = Talisman(app,content_security_policy=csp)
cors = CORS(app,resource=r'/profile/')
paranoid.redirect_view = 'localhost:5000/register'



# session expiry, still need error emssage
@app.before_request
def before_request():
    if current_user.is_authenticated:
        last_login = session['last_login']
        time = datetime.datetime.now() - last_login
        print(time.seconds)
        if time.seconds > 900:  # 30minutes
            logout_user()
            session.destroy()
            resp = make_response(redirect(url_for('home_page')))
            if resp.headers['Location'] == '/':
                return resp
    # print(psutil.net_io_counters())
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(days=1)
    session.modified = True
    g.user = current_user
    test.kvsession_extension.cleanup_sessions(app)

@app.after_request
def after_request(response):
    # if datetime.datetime.now() - session['created'] > app.permanent_session_lifetime:
    #     test.kvsession_extension.cleanup_sessions(app)
    return response

def login_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        try:
            if not current_user.is_authenticated:
                abort(404)
            else:
                return f(*args,**kwargs)
        except:
            abort(404)
    return wrap

def verify_require(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if current_user.is_authenticated:
            if current_user.verified == 0:
                resp = make_response(redirect(url_for('users.unconfirmed')))
                if resp.headers['Location'] == '/unconfirmed':
                    return resp
                else:
                    abort(404)
                # return redirect(url_for('users.unconfirmed'))
            else:
                return f(*args,**kwargs)
        else:
            return f(*args, **kwargs)
    return wrap


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    session.regenerate()
    return '<h3>Sorry server encountered an error. Please try again by refreshing your browser</h3>'


@app.route('/')
@verify_require
@cross_origin(allow_headers=['Content-Type'],origins=['https://www.google.com'],support_credentials=True)
def home_page():
    if 'created' not in session:
        session['created'] = datetime.datetime.now()
    print(session['created'])
    searchForm = SearchForm()
    print(request.headers.get('X-Forwarded-For', request.remote_addr))
    twst = request.headers.get('X-Forwarded-For', request.remote_addr)
    print(paranoid._get_remote_addr())
    # print(test.session)
    # # for key in red.scan_iter():
    # #     print(json.loads(red.get(key)))
    # d = socket.gethostname()
    # print(socket.gethostbyname(d))
    # allowed_content_type =
    print(session)
    response = make_response(render_template('index.html',searchForm=searchForm,ip=twst))
    return response
@app.route('/login')
def login():
    print(session)
    searchForm = SearchForm()
    errors = ''
    if current_user.is_authenticated:
        resp = make_response(redirect(url_for('home_page')))
        if resp.headers['Location'] == '/':
            return resp
    form = LoginForm()
    if_prod = os.environ.get('IS_PROD')
    return render_template('login.html',form=form,errors=errors,searchForm=searchForm,if_prod=if_prod)

@app.route('/register')
def register():
    searchForm = SearchForm()
    form = RegisterForm()
    return render_template('register.html',form=form,searchForm=searchForm)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.destroy()
    print(session)
    resp = make_response(redirect(url_for('home_page')))
    if resp.headers['Location'] == '/':
        return resp
    else:
        abort(404)

#can consider as broken access control
@app.route('/profile/<username>')
@verify_require
@login_required
def profile(username):
    searchForm = SearchForm()
    print(current_user.is_active)
    if current_user.is_authenticated and current_user.username == username:
        return render_template('profile.html', active='profile',searchForm=searchForm)
    else:
        abort(404)
        log.logger.warning('An attempt to access to this page without authenticcation  was deny')

@app.route('/profile/<username>/account')
@verify_require
def account(username):

    searchForm = SearchForm()
    if current_user.is_authenticated and current_user.username == username:
        print(current_user.account.credit_card)
        credit_card = current_user.account.credit_card
        if current_user.account.credit_card != None:

            key_vault = vault.Vault()
            credit_card =  key_vault.decrypt(current_user.account.credit_card,username)
            key_vault.close_all_connections()
            return render_template('account.html', searchForm=searchForm, credit_card=credit_card)
        else:
            return render_template('account.html', searchForm=searchForm, credit_card=credit_card)
    else:
        log.logger.warning('An attempt to access to this page without authenticcation  was deny')
        abort(404)


@app.route('/profile/<username>/account/update')
@verify_require
def account_update_page(username):
    searchForm = SearchForm()
    if current_user.is_authenticated and current_user.username == username:
        form = AccountForm()
        return render_template('accountUpdate.html',form=form,searchForm=searchForm)
    else:
       log.logger.warning('An attempt to access to this page without authenticcation  was deny')
       abort(404)

def adminLogin():
    pass
    # if vulnerability remove these and check for domain hostname
    # current_location = utils.get_location()
    # target_point = [{'lat':1.3793037,'lng':103.8476829}]
    # current_point = [{'lat':current_location[0],'lng':current_location[1]}]
    # radius = 0.1
    # distance = utils.haversine(target_point[0]['lng'],target_point[0]['lat'],float(current_point[0]['lng']),float(current_point[0]['lat']))
    # if distance < radius:

    # form = AdminLoginForm()
    # return render_template('private/adminLogin.html',form=form)
    # else:
    #     abort(403)

@app.route('/reset')
def reset_link():
    if current_user.is_authenticated:
        abort(404)
    searchForm = SearchForm()
    errors=''
    form = EmailForm()
    return render_template('reset.html',form=form,errors=errors,searchForm=searchForm)


@app.route('/support')
@verify_require
def support():
    searchForm = SearchForm()
    form = SupportForm()
    return render_template('support.html',searchForm=searchForm,form=form)

@app.route('/catalog')
@verify_require
def catalog():
    searchForm = SearchForm()
    products = Models.database.session.query(Models.Product).all()
    return render_template('shop.html',products=products,itemCount=len(products),searchForm=searchForm)

@app.route('/catalog/<productid>' , methods=['POST','GET'])
@verify_require
def single_product_detail(productid):
    searchForm = SearchForm()
    product = Models.Product.query.filter_by(productid=productid).first()
    return render_template('single_product_details.html',product=product,searchForm=searchForm)

@app.route('/result')
@verify_require
def search_result():
    searchForm = SearchForm()
    query = request.args.get('query')
    search = "%{}%".format(query)
    result = Models.database.session.query(Models.Product).filter(or_(Models.Product.Name.ilike(search),Models.Product.Description.ilike(search),Models.Product.model.ilike(search))).all()

    print(result)
    return render_template('search.html',product=result,itemCount=len(result),query=query,searchForm=searchForm), 201

@app.route('/current')
def current_password():
    searchForm = SearchForm()
    if current_user.is_authenticated:
        form = ChangePasswordForm()
        return render_template('current_password.html',form=form, searchForm=searchForm)
    else:
        abort(404)


if __name__ == '__main__':
    app.config.update(
        SESSION_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = 'SameSite'

    )
    # app.config.update(
    #     SESSION_COOKIE_SAMESITE='LAX'
    # )
    if os.environ.get('IS_PROD',None):
        app.config.update(
            SESSION_COOKIE_HTTPONLY = True,
            SESSION_COOKIE_SECURE = True,
            SESSION_COOKIE_SAMESITE='SameSite'

        )
        app.run()
    else:
        app.run(debug=True,port=9999)