from flask import jsonify,request,flash,Flask,render_template,redirect,session,url_for,Response,abort,json,make_response,g
from flask_wtf.csrf import CSRFProtect,CSRFError
from flask_sqlalchemy import *
from techmarketplace.Form import RegisterForm, LoginForm,AdminLoginForm,TwoFactorForm
from techmarketplace import aconfig
from flask_login import login_user,logout_user,current_user
from flask_talisman import Talisman
from flask_paranoid import Paranoid
import io
import pyqrcode
import os
import datetime




app = aconfig.create_app()



with app.app_context():
    from techmarketplace.api.routes import adminAPI
    from techmarketplace import AdminModels,server_session

    app.register_blueprint(adminAPI.admin_blueprint)
    # try:
    #     x = AdminModels.Admin('testUser', 'password123', 96279135)
    #     AdminModels.database.session.add(x)
    #     AdminModels.database.session.commit()
    # except:
    #     AdminModels.database.session.rollback()

csp = {
        'default-src': ['\'self\'','https://fonts.googleapis.com/css'],
        'img-src': '\'self\' data:',
        'style-src': '\'unsafe-inline\' \'self\'',
        'script-src': '\'self\''

}
talisman = Talisman(app,content_security_policy=csp)
paranoid = Paranoid(app)
paranoid.redirect_view = 'https://google.com'

@app.before_request
def before_request():
    if current_user.is_authenticated:
        last_login = session['last_login']
        time = datetime.datetime.now() - last_login
        print(time.seconds)
        if time.seconds > 900:  # 30minutes
            logout_user()
            session.clear()
            resp = make_response(redirect(url_for('login')))
            if resp.headers['Location'] == '/':
                return resp
    # print(psutil.net_io_counters())
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=15)
    session.modified = True
    g.user = current_user


@app.route('/')
def login():
    print(session)
    if 'user' in session or current_user.is_authenticated:
        abort(404)
    form = AdminLoginForm()
    return render_template('adminLogin.html',form=form)

@app.route('/twofactor')
def twofactor():

    if 'user' in session:
        admin = AdminModels.Administrator.query.filter_by(username=session['user']).first()
        if admin.TFA:
            form = TwoFactorForm()
            return render_template('twofactorPage.html',form=form) ,200 ,{
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
        else:
            abort(404)
    else:
        abort(404)

@app.route('/TwoFactorSetUp')
def TwoFactorSetup():
    if 'user' not in session:
        abort(404)
    admin = AdminModels.Administrator.query.filter_by(username=session['user']).first()
    if admin is None:
        abort(404)
    if admin.TFA:
        abort(404)
    form = TwoFactorForm()
    return render_template('TwoFactorSetUp.html',form=form),200 ,{
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

# @app.route('/a')
# def admin_customer():
#     return self.render('index.html')

@app.route('/permissions/<int:adminid>')
def permissions(adminid):
    dataDict = {}
    q=str()
    p=str()
    admin = str()
    role= str()
    current_admin_role = current_user.adminrole
    print(current_admin_role)
    current_role_type = [roles.type for roles in current_admin_role]
    if 'System Administrator' in current_role_type:
        admin =  AdminModels.Administrator.query.get(adminid)
        query = AdminModels.admin_roles.query.join(AdminModels.Administrator).join(AdminModels.roles).filter(
            AdminModels.admin_roles.adminid == adminid).all()
        p = [q.permission for q in query]
        print(p)
        if admin != None:
            role = admin.adminrole # [<Role 1>]
            for roles in role:
                q = AdminModels.database.session.query(AdminModels.admin_roles).join(AdminModels.Administrator).join(AdminModels.roles).filter(AdminModels.admin_roles.adminid == adminid and AdminModels.admin_roles.roleid == roles.roleid).all()


    else:
        abort(403)

    return render_template('permission.html',admin=admin,role=role,permission=p)

if __name__ == '__main__':
    # this works
    # app.config.update(
    #     SESSION_COOKIE_SECURE = True,
    #     SESSION_COOKIE_HTTPONLY = True,
    #     SESSION_COOKIE_SAMESITE='Lax',
    # )
    app.run(debug=True,host='127.0.0.1',port=5001)