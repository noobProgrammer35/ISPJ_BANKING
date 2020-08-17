from flask import Blueprint,render_template,request,redirect,url_for,session,jsonify,flash,abort,current_app,json,escape,Markup,make_response
from flask_recaptcha import ReCaptcha
import pickle
from flask_mail import Mail,Message
from flask_login import current_user,login_user,logout_user
from itsdangerous import URLSafeTimedSerializer
from mysql import connector
from techmarketplace import utils,Models,vault,log
from techmarketplace.Form import RegisterForm, LoginForm,AccountForm,EmailForm,PasswordResetForm,SearchForm,SupportForm, ChangePasswordForm
from werkzeug.datastructures import Headers
import os
import redis
from uuid import uuid4
from datetime import timedelta, datetime
import socket
import requests



users_blueprint = Blueprint('users',__name__,template_folder='templates')





# @users_blueprint.route('/register',methods=['POST'])  # create user
# def register():
#     form = RegisterForm(request.form)
#     if form.validate_on_submit():
#         username = form.username.data
#         fname = form.fname.data
#         lname = form.lname.data
#         contact = form.contact.data
#         email = form.email.data
#         password = form.confirm.data
#         try:
#             #open connection
#             conn = connector.MySQLConnection(**db)
#             mycursor = conn.cursor(prepared=True)
#             #senstive data exposure
#             password_salt = utils.generate_salt()
#             password_hash = utils.generate_hash(password,password_salt)
#             insert_tuple = (username,fname,lname,contact,email,password_hash,password_salt,0)
#             mycursor.execute('SELECT username,email FROM users WHERE username=%s or email=%s LIMIT 1',(username,email))
#             result = mycursor.fetchall()
#             for x,y in result:
#                 print(x)
#             row = mycursor.rowcount
#             print(row)
#             if row == 0:
#                 mycursor.execute('INSERT INTO users (username,fname,lname,contact,email,password_hash,password_salt,verified) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)',insert_tuple)
#                 conn.commit()
#                 token = utils.generate_token(email)
#                 print(token)
#                 confirm_url = url_for('users.confirm_email',token=token,_external=True)
#                 html = render_template('activate.html',confirm_url=confirm_url)
#                 subject = 'Please confirm your account'
#                 utils.send_email(email,subject,html)
#                 flash('dog shit')
#                 return redirect(url_for('login'))
#             else:
#                 for username,email in result:
#                     if username == username and email ==  email:
#                         flash('Username and email existed please use another one!')
#                     elif username == username:
#                         flash('This is an existing username, please choose another one')
#                     elif email == email:
#                         flash('This is an existing email, please choose another one')
#                 return redirect(url_for('register'))
#         except connector.Error as error:
#             print(error)
#         finally:
#             if conn.is_connected():
#                 mycursor.close()
#                 conn.close()
#
#     else:
#         print(form.errors)
#     return render_template('register.html',form=form), 200

@users_blueprint.route('/register',methods=['POST','GET'])
def register():
    if current_user.is_authenticated:
        abort(404)
    searchForm = SearchForm()
    form = RegisterForm()

    if form.validate_on_submit():
        if request.content_type != r'application/x-www-form-urlencoded':
            log.logger.error('Incorrect content type format')
            abort(404)

        if utils.banned_characters(form.username.data) or utils.banned_characters(form.password.data) or utils.banned_characters(form.fname.data) or utils.banned_characters(form.lname.data) or utils.banned_characters(form.email.data):
            print('d')
            log.logger.critical('Malicious characters detected in register form',extra={'custom_dimensions': {'Source': request.remote_addr}})
            abort(404)

        if utils.banned_characters(form.confirm.data.upper(),matches='({0})'.format(str(escape(form.username.data.upper())))):
            flash('Password should not contain anything related to your username. Please try again!')
            resp = make_response(redirect(url_for('register')))
            if resp.headers['Location'] == '/register':
                return resp

        if os.environ.get('IS_PROD',None):
            if utils.banned_characters(form.confirm.data.upper(),matches='(PASSWORD)') or utils.banned_characters(form.confirm.data.upper(), matches='(PASSWORD)') or utils.banned_characters(form.confirm.data.upper(),matches='(ADMIN)'):
                flash('This password is either too common and subsceptiple to hackers or password contain words like \"username\" or \"password\" or \"admin\"')
                resp = make_response(redirect(url_for('register')))
                if resp.headers['Location'] == '/register':
                    return resp
        else:
            if utils.read_common_password(form.confirm.data) or utils.banned_characters(form.confirm.data.upper(),matches='(PASSWORD)') or utils.banned_characters(form.confirm.data.upper(),matches='(PASSWORD)') or utils.banned_characters(form.confirm.data.upper(),matches='(ADMIN)'):
                flash('This password is either too common and subsceptiple to hackers or password contain words like \"username\" or \"password\" or \"admin\"')
                resp = make_response(redirect(url_for('register')))
                if resp.headers['Location'] == '/register':
                    return resp

        username = Models.Customer.query.filter_by(username=str(escape(form.username.data))).first()
        email = Models.Customer.query.filter_by(email=str(escape(form.email.data))).first()
        if email is None and username is None:
            user = ''
            try:
                user = Models.Customer(str(escape(form.username.data)),str(escape(form.fname.data)),str(escape(form.lname.data)),form.contact.data,str(escape(form.confirm.data)),0,str(escape(form.email.data)))
                Models.database.session.add(user)
                Models.database.session.commit()
            except Exception as errors:
                print('test')
                log.logger.exception(errors)
                Models.database.session.rollback()
            token = utils.generate_token(user.email)
            confirm_url = url_for('users.confirm_email',token=token, _external=True)
            html = render_template('activate.html',confirm_url=confirm_url)
            subject = 'Please confirm your account'
            utils.mailgun_send_message(form.email.data,subject,html)
            log.logger.info('A new user has sucessfully registered with username of {0}'.format(form.username.data),extra={'custom_dimensions':{'Source':request.remote_addr}})
            resp = make_response(redirect(url_for('login')))
            if resp.headers['Location'] == '/login':
                return resp
        else:
            if email is not None and username is not None:
                flash('Username and email exist')
            elif email is not None:
                flash('Email exist')
            elif username is not None:
                flash('Username exist')
            return redirect(url_for('register'))
    else:
        print(form.username.data)
    return render_template('register.html',form=form,searchForm=searchForm)




# @users_blueprint.route('/login',methods=['POST'])
# def login():
#     errors = 'dddd'
#     form = LoginForm()
#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data
#         try:
#             conn = connector.MySQLConnection(**db)
#             mycursor = conn.cursor(prepared=True,)
#             # vulnerable code
#             # sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
#             mycursor.execute("SELECT*FROM users where username=%s LIMIT 1;", (username,))
#             account = mycursor.fetchone()
#             conn.commit()
#             if account:
#                 saved_password_salt = account[7]
#                 saved_password_hash = account[6]
#                 password_hash = utils.generate_hash(password,saved_password_salt)
#                 if password_hash == saved_password_hash:
#                     session['username'] = account[1]
#                     session['email'] = account[5]
#                     session['verified'] = account[8]
#                     r = requests.post('https://www.google.com/recaptcha/api/siteverify',
#                                       data={'secret':
#                                                 '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',
#                                             'response':
#                                                 request.form['g-recaptcha-response']})
#                     google_response = json.loads(r.text)
#                     print(google_response)
#                     if google_response['success']:
#                         if account[8] == 1:
#                             return redirect(url_for('home_page'))
#                         else:
#                             return redirect(url_for('users.unconfirmed'))
#                     else:
#                         errors = 'Please capture the recaptcha'
#
#                 else:
#                    errors= 'invalid username or password'
#
#             else:
#                 errors = 'Invalid username or password'
#         except connector.Error as error:
#             print(error)
#         finally:
#             if conn.is_connected():
#                 mycursor.close()
#                 conn.close()
#     else:
#         print(form.errors)
#     print(errors)
#     return render_template('login.html',form=form,errors=errors)

@users_blueprint.route('/login',methods=['POST'])
def login():
    searchForm = SearchForm()
    if current_user.is_authenticated:
        # print(current_user.username)
        abort(404)
    errors = ''
    form = LoginForm()
    if form.validate_on_submit():
        if utils.banned_characters(form.username.data) or utils.banned_characters(form.password.data):
            log.logger.critical('Malicious characters such as \'\"<>#/ detected')
            print('d')
            errors = 'Invalid username or password'
            abort(404)

        print(form.username.data)
        if request.content_type  != r'application/x-www-form-urlencoded':
            log.logger.error('Incorrect content format')
            abort(404)
        user = Models.Customer.query.filter_by(username=str(escape(form.username.data))).first()
        if user is not None:
            if user.failed_login_time is not None:
                date = user.failed_login_time
                now = datetime.now()
                span = now - date
                print(span.days)
                if span.days > 1:
                    user.failed_attempt = 0
                    Models.database.session.commit()

            saved_password_hash = user.password_hash
            saved_password_salt = user.password_salt
            password_hash = utils.generate_hash(str(escape(form.password.data)),saved_password_salt)
            if password_hash == saved_password_hash:
                if user.verified == 1 and user.failed_attempt < 5:
                    print('verified authen')
                    u = Models.Customer.query.get(user.userid)
                    session.destroy()
                    login_user(u)
                    try:
                        user.failed_attempt = 0
                        Models.database.session.commit()
                    except:
                        Models.database.session.rollback()
                    session.regenerate()
                    session['last_login'] = datetime.now()
                    response = make_response(redirect(url_for('home_page')))
                    log.logger.info('{0} successfully logs into his account'.format(u.username))
                    resp = make_response(redirect(url_for('home_page')))
                    print(resp.headers['Location'])
                    if resp.headers['Location'] == '/':
                        return resp
                    else:
                        abort(404)
                elif user.verified == 0 and user.failed_attempt < 5:
                    u = Models.Customer.query.get(user.userid)
                    login_user(u)
                    try:
                        user.failed_attempt = 0
                        Models.database.session.commit()
                    except:
                        Models.database.session.rollback()
                    session['last_login'] = datetime.now()
                    log.logger.warning('{0} successfully logs into his account without activating it'.format(u.username))
                    resp = make_response(redirect(url_for('users.unconfirmed')))
                    if resp.headers['Location'] == '/unconfirmed':
                        return resp
                    else:
                        abort(404)
                elif user.failed_attempt >= 5:
                    abort(404)
            else:
                if user.failed_attempt >= 5:
                    abort(404)
                try:
                    if user.failed_attempt < 5:
                        errors = 'Invalid username or password'
                        user.failed_attempt += 1
                        if user.failed_attempt == 5:
                            utils.mailgun_send_message(user.email,'test','<p>dwdwd</p>')
                        user.failed_login_time = datetime.now()
                        Models.database.session.commit()
                    elif user.failed_attempt >= 5:
                        abort(404)
                except:
                    Models.database.session.rollback()

        else:
            errors = 'Invalid username or password'

    else:

        print(form.errors)

    return render_template('login.html',form=form,errors=errors,searchForm=searchForm)



# checked if confirm later()
@users_blueprint.route('/confirm/<token>')
def confirm_email(token):
    # try:
    #     print(token)
    #     email = utils.confirmation_token(token)
    #     print(email)
    #     conn = connector.MySQLConnection(**db)
    #     mycursor = conn.cursor()
    #     mycursor.execute('update users set verified = 1 where email=%s',(email,))
    #     conn.commit()
    # except connector.Error as error:
    #     print(error)
    # finally:
    #     mycursor.close()
    #     conn.close()
    email = utils.confirmation_token(token)
    if not email:
        flash('Token expired. Please identify yourself first by logging in to request for another token')
        resp = make_response(redirect(url_for('login')))
        if resp.headers['Location'] == '/login':
            return resp
    user = Models.Customer.query.filter_by(email=email).first()
    user.verified = True
    Models.database.session.commit()
    account = Models.Account(user.userid)
    print(account)
    Models.database.session.add(account)
    Models.database.session.commit()
    log.logger.info('{0} successfully confirm and activated his account through email'.format(user.username))
    resp = make_response(redirect(url_for('home_page')))
    if resp.headers['Location'] == '/':
        return resp
    else:
        abort(404)


@users_blueprint.route('/unconfirmed')
def unconfirmed():
    if current_user.is_authenticated:
        if current_user.verified == 0:
            searchForm = SearchForm()
            return render_template('unconfirm.html',searchForm=searchForm)
        else:
            abort(404)
    else:
        abort(404)

@users_blueprint.route('/resend')
def resend():
    token = utils.generate_token(current_user.email)
    confirm_url = url_for('users.confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = 'Please confirm your account'
    utils.mailgun_send_message(current_user.email,subject,html)
    flash('Email sent!')
    resp = make_response(redirect(url_for('users.unconfirmed')))
    print(resp.headers['Location'])
    if resp.headers['Location'] == '/unconfirmed':
        return resp
    else:
        abort(404)


@users_blueprint.route('/profile/<username>/account/update',methods=['POST'])
def accountUpdate(username):
    if current_user.is_authenticated and current_user.username == username:
        form = AccountForm()
        searchForm = SearchForm()
        if form.validate_on_submit():
            if utils.banned_characters(form.credit_card.data):
                log.logger.critical('Malicious Character detected in /profile/{0}/account/update'.format(username))
                logout_user()
                abort(404)
            if request.content_type != 'application/x-www-form-urlencoded':
                log.logger.error('Incorrect content type format found in /profile/{0}/account/update'.format(username))
                abort(404)
            key_vault = vault.Vault()
            try:
                key_vault.key_client.get_key(username)
            except:
                key_vault.set_key(username,4096,key_vault.key_ops)
            user = Models.Customer.query.filter_by(username=username).first()
            user.account.payment_method = form.payment_method.data
            user.account.credit_card = key_vault.encrypt(username,form.credit_card.data)
            user.account.address = form.address.data
            Models.database.session.commit()
            key_vault.key_client.close()
            key_vault.secret_client.close()
            log.logger.info('{0} successfuly updated his/her account'.format(user.username))
            resp = make_response(redirect(url_for('account',username=username)))
            print(resp.headers['Location'])
            if resp.headers['Location'] == '/profile/'+current_user.username+'/account':
                return resp
        else:
            log.logger.exception(form.errors)
            print(form.errors)
        return render_template('accountUpdate.html', form=form,searchForm=searchForm)
    else:
        abort(404)


@users_blueprint.route('/reset',methods=['POST'])
def reset_link():
    searchForm = SearchForm()
    error = ''
    form = EmailForm()
    if form.validate_on_submit():
        if request.content_type != r'application/x-www-form-urlencoded':
            log.logger.error('Incorrect content format sent detected in /reset route')
            abort(404)
        if Models.Customer.query.filter_by(email=str(escape(form.email.data))).first():
            token = utils.generate_token(form.email.data)
            password_reset_url = url_for('users.reset_password_link',token=token,_external=True)
            html = render_template('reset_email.html',password_reset_url=password_reset_url)
            if os.environ.get('IS_PROD',None):
                utils.mailgun_send_message(form.email.data,'Password Recovery',html)
            else:
                utils.send_email(form.email.data,'Password Recovery',password_reset_url=password_reset_url)
            flash('WE have emailed you the password link to reset!')
            resp = make_response(redirect(url_for('reset_link')))
            if resp.headers['Location'] == '/reset':
                return resp
            else:
                abort(404)

        else:
            error = 'This email is not registered with us!'

    return render_template('reset.html',form=form,errors=error,searchForm=searchForm)


@users_blueprint.route('/reset/<token>',methods=['GET','POST'])
def reset_password_link(token):
    if current_user.is_authenticated:
        abort(404)
    searchForm = SearchForm()
    email = utils.confirmation_token(token)
    print(email)
    if not email:
        flash('This link has expired!')
        resp = make_response(redirect(url_for('login')))
        if resp.headers['Location'] == '/login':
            return resp
        else:
            abort(404)
    form = PasswordResetForm()
    if form.validate_on_submit():
        if request.content_type != 'application/x-www-form-urlencoded':
            log.logger.error('Incorrect content format found!')
            abort(404)
        try:
            user = Models.Customer.query.filter_by(email=email).first()
        except:
            flash('Invalid email')
            return redirect(url_for('login'))

        salt = user.generate_salt()
        user.password_salt = salt
        user.password_hash = user.generate_hash(form.password.data,salt)
        Models.database.session.commit()
        log.logger.info('{0} has succesfully reset his password'.format(user.username))
        resp = make_response(redirect(url_for('login')))
        if resp.headers['Location'] == '/login':
            return resp
        else:
            abort(404)
    return render_template('reset_password.html',form=form,token=token,searchForm=searchForm)

@users_blueprint.route('/search',methods=['POST'])
def search():
    searchForm = SearchForm()
    if searchForm.validate_on_submit():
        if utils.banned_characters(searchForm.search.data):
            log.logger.critical('Malicious character detected in search')
            abort(404)
        if request.content_type != r'application/x-www-form-urlencoded':
            print('dd')
            abort(404)
        query = searchForm.search.data
        resp = make_response(redirect(url_for('search_result',query=escape(query))))
        return resp
    # if request.method == 'POST':
    #     query = request.form['search']
    #
    #     return redirect(url_for('search_result',query=query))

@users_blueprint.route('/support',methods=['POST'])
def support():
    searchForm = SearchForm()
    form = SupportForm()
    if form.validate_on_submit():
        if request.content_type != r'application/x-www-form-urlencoded':
            log.logger.error('Incorrect request content format at /support route')
            abort(404)
        if utils.banned_characters(form.subject.data) or utils.banned_characters(form.message.data,matches='[/\\<>%=]') or utils.banned_characters(form.name.data) or utils.banned_characters(form.email.data):
            log.logger.critical('Malicious character detected in support route')
            abort(404)
        try:
            # mail = Mail(current_app)
            # msg = Message(
            #     subject = form.subject.data,
            #     recipients=['piethonlee123@gmail.com'],
            #     body=form.message.data,
            #     sender=form.name.data,
            #     reply_to=form.email.data
            # )
            # mail.send(msg)
            utils.mailgun_send_messageV2('piethonlee123@gmail.com',form.subject.data,form.message.data,form.email.data)
            flash('Email has sent to u')
            resp = make_response(redirect(request.url))
            if resp.headers['Location'] == '/support':
                return resp
        except Exception as message:
            abort(404)
            log.logger.exception(message)

    return render_template('support.html',searchForm=searchForm,form=form)


@users_blueprint.route('/current', methods=['POST'])
def current():
    searchForm = SearchForm()
    if current_user.is_authenticated:
        form = ChangePasswordForm()
        if form.validate_on_submit():
            if request.content_type != r'application/x-www-form-urlencoded':
                log.logger.error('Incorrect request content format at /current route')
                abort(404)
            if utils.banned_characters(form.currentPassword.data):
                 log.logger.critical('Malicious character detected in support route. An attempt to inject is possible')
                 abort(404)
            user = Models.Customer.query.filter_by(username=current_user.username).first()
            saved_hash= user.password_hash
            password_hashed = utils.generate_hash(form.currentPassword.data,user.password_salt)
            if saved_hash == password_hashed:

                if utils.banned_characters(form.confirm.data.upper(),matches='({0})'.format(str(escape(current_user.username.upper())))):
                    flash('Password should not contain anything related to your username. Please try again!')
                    resp = make_response(redirect(url_for('current_password')))
                    if resp.headers['Location'] == '/current':
                        return resp
                elif utils.read_common_password(form.confirm.data) or utils.banned_characters(form.confirm.data.upper(),matches='(PASSWORD)') or utils.banned_characters(form.confirm.data.upper(), matches='(PASSWORD)') or utils.banned_characters(form.confirm.data.upper(), matches='(ADMIN)'):
                    flash('This password is either too common and subsceptiple to hackers or password contain words like \"username\" or \"password\" or \"admin\"')
                    resp = make_response(redirect(url_for('current_password')))
                    if resp.headers['Location'] == '/current_password':
                        return resp
                else:
                    try:
                        user = Models.Customer.query.filter_by(username=current_user.username).first()
                        new_salt = utils.generate_salt()
                        new_hash = utils.generate_hash(form.confirm.data,new_salt)
                        user.password_salt = new_salt
                        user.password_hash = new_hash
                        Models.database.session.commit()
                        logout_user()
                        session.destroy()
                        flash('Password has changed,please try to login with new credential')
                        resp = make_response(redirect(url_for('login')))
                        if resp.headers['Location'] == '/login':
                            return resp
                    except:
                        Models.database.session.rollback()


            else:
                flash('Invalid current password')
                resp = make_response(redirect(url_for('current_password')))
                if resp.headers['Location'] == '/current':
                    return resp


    else:
        abort(404)


