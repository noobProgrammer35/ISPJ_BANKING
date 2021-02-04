from email.mime.text import MIMEText
from flask import Blueprint,render_template,request,redirect,url_for,session,jsonify,flash,abort,current_app,json,make_response
from techmarketplace.Form import AdminLoginForm,TwoFactorForm
from techmarketplace import AdminModels,utils
from flask_login import login_user,logout_user,current_user
from techmarketplace import utils
from werkzeug.utils import secure_filename
from datetime import datetime
from sqlalchemy import and_
import pyqrcode
import os
import io
import subprocess
import vulners
import smtplib

if not os.environ.get('IS_PROD'):
    from techmarketplace import Configuration,classification


admin_blueprint = Blueprint('admins',__name__,template_folder='backend')

#show qr code to only those wh havent activate 2FA
# steps verify login credential > verify token > login
# if not activated 2fa prompt to activate page whicyh is qr code, in activate page make a textfield to verify token if correct then tfa enabled for that user

@admin_blueprint.route('/',methods=['POST'])
def login():
    if 'user' in session  or current_user.is_authenticated:
        abort(404)
    form = AdminLoginForm()
    if form.validate_on_submit():
        username =  form.username.data
        password = form.password.data
        admin = AdminModels.Administrator.query.filter_by(username=username).first()
        if admin != None:
            saved_password_salt = admin.password_salt
            password_hash = utils.generate_hash(password,saved_password_salt)
            if admin.verify_password(password_hash):
                # current = AdminModels.Administrator.query.get(admin.adminid)
                # login_user(current)
                if not admin.TFA:
                    session['user'] = admin.username
                    session['last_login'] = datetime.now()
                    print(session)
                    return redirect(url_for('TwoFactorSetup'))
                else:
                    session['user'] = admin.username
                    session['last_login'] = datetime.now()
                    return redirect(url_for('twofactor'))
            else:
                print(3)
        else:
            print(2)
    else:
        print(1)
    return render_template('adminLogin.html',form=form)



@admin_blueprint.route('/qrcode')
def qrcode():
    if 'user' not in session:
        abort(404)
    user = AdminModels.Administrator.query.filter_by(username=session['user']).first()
    if user is None:
        abort(404)
    print(user)
    url = pyqrcode.create(user.get_totp_url())
    stream = io.BytesIO()
    url.svg(stream, scale=5)
    # remove cache
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@admin_blueprint.route('/twofactor',methods=['POST'])
def authenticate():
    if 'user' not in session:
        abort(404)
    user = AdminModels.Administrator.query.filter_by(username=session['user']).first()
    if user is None:
        abort(404)
    if not user.TFA:
        abort(404)
    del session['user']
    print(user.username)
    form = TwoFactorForm()
    if form.validate_on_submit():
        print('dadadadadadad')
        token = form.token.data
        if user.verify_otp(token):
            current = AdminModels.Administrator.query.get(user.adminid)
            login_user(current)
            return redirect(url_for('admin.index'))
    else:
        print('not validated')

    return render_template('twofactorPage.html',form=form)

@admin_blueprint.route('/TwoFactorSetUp',methods=['POST'])
def TFASetup():
    if 'user' not in session:
        abort(404)
    admin = AdminModels.Administrator.query.filter_by(username=session['user']).first()
    if admin is None:
        abort(404)
    if admin.TFA:
        abort(404)
    form = TwoFactorForm()
    if form.validate_on_submit():

        if admin.verify_otp(form.token.data):
            admin.TFA = True
            AdminModels.database.session.commit()
            del session['user']
            return redirect(url_for('login'))
        else:
            del session['user']
            flash('Key in wrongly please re login to key in again')
            return redirect(url_for('TwoFactorSetup'))
    return render_template('TwoFactorSetUp.html',form=form)

@admin_blueprint.route('/product_create',methods=['POST','GET'])
def product_create():
    if request.method == 'POST':
        name = request.form['Name']
        description = request.form['Description']
        stock = request.form['stock']
        price = request.form['price']
        Image = request.files['Image']
        Image2 = request.files['Image2']
        model = request.form['model']

        products = AdminModels.Product.query.filter_by(model=model).first()
        if products is None:

            if utils.banned_characters(name) or utils.banned_characters(description) or utils.banned_characters(model) :
                flash('Suspcious character detected. Please do not try to do malicious stuff')
                return redirect('/admin/product/new')
            if name == '' or description == '' or model =='':
                flash('Please fill in everything')
                return redirect('/admin/product/new')

            if price == '' or stock == '':
                flash('Stock or price must be integer')
                return redirect('/admin/product/new')

            if Image.filename=='' or Image2.filename == '':
                flash('No selected file')
                return redirect('/admin/product/new')
            if Image and Image2 and utils.allowed_file(Image.filename) and utils.allowed_file(Image2.filename):
                ImageName = secure_filename(Image.filename)
                ImageName2 = secure_filename(Image2.filename)
                path = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName)
                path2 = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName2)
                Image.save(path)
                Image2.save(path2)
                product = AdminModels.Product(name, description, stock, price, ImageName, ImageName2,model)
                AdminModels.database.session.add(product)
                AdminModels.database.session.commit()
                return redirect(url_for('product.index_view'))
            else:
                flash('Inappoporiate file type')
                return redirect('/admin/product/new')
        else:
            flash('This model has already exist in our inventory')
            return redirect('/admin/product/new')


@admin_blueprint.route('/edit_product/<prouctid>',methods=['POST'])
def edit(productid):
    if request.method == 'POST':
        name = request.form['Name']
        description = request.form['Description']
        stock = request.form['stock']
        price = request.form['price']
        Image = request.files['Image']
        Image2 = request.files['Image2']
        model = request.form['model']
        product = AdminModels.Product.query.filter_by(productid=productid).first()
        if utils.banned_characters(name) or utils.banned_characters(description) or utils.banned_characters(model):
            flash('Suspcious character detected. Please do not try to do malicious stuff')
            return redirect('/admin/product/edit')
        if name == '' or description == '' or model == '':
            flash('Please fill in everything')
            return redirect('/admin/product/edit/?id={0}&url=%2Fadmin%2Fproduct%2F'.format(product.productid))

        if price == '' or stock == '':
            flash('Stock or price must be integer')
            return redirect('/admin/product/edit/?={0}&url=/admin/product/'.format(product.productid))

        if Image.filename == '' or Image2.filename == '':
            flash('No selected file')
            return redirect(url_for('product.edit_view'))
        if Image and Image2 and utils.allowed_file(Image.filename) and utils.allowed_file(Image2.filename):
            if product.model == model:
                product.Name = name
                product.Description = description
                product.stock= stock
                product.price = price
                ImageName = secure_filename(Image.filename)
                ImageName2 = secure_filename(Image2.filename)
                path = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName)
                path2 = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName2)
                Image.save(path)
                Image2.save(path2)
                product.Image = ImageName
                product.Image2 = ImageName2
                product.model = model
                AdminModels.database.session.commit()
                return redirect(url_for('product.index_view'))

            else:
                models = AdminModels.Product.query.filter_by(model=model).first()
                if models is None:
                    product.Name = name
                    product.Description = description
                    product.stock = stock
                    product.price = price
                    ImageName = secure_filename(Image.filename)
                    ImageName2 = secure_filename(Image2.filename)
                    path = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName)
                    path2 = os.path.join(current_app.config['UPLOAD_FOLDER'], ImageName2)
                    Image.save(path)
                    Image2.save(path2)
                    product.Image = ImageName
                    product.Image2 = ImageName2
                    product.model = model
                    AdminModels.database.session.commit()
                    return redirect(url_for('product.index_view'))


@admin_blueprint.route('/backup_database',methods=['GET','POST'])
def backup_database():
    if request.method == 'POST':
        table = request.form.get('type_select')
        if AdminModels.is_permission_valid('BACKUP ADMINISTRATOR','C'):
            utils.database_backup(table)
            flash('Files backup successfully to D:/ManualBackup_Database', 'success')
            return redirect('/admin/backup')
        else:
            flash('You do not have the permission to do this action', 'error')
            return redirect('/admin/backup')


@admin_blueprint.route('/source_code_backup',methods=['GET','POST'])
def code_files_backup():
    if request.method == 'POST':
        backup_type = request.form.get('code_select')
        if AdminModels.is_permission_valid('BACKUP ADMINISTRATOR', 'C'):
            code_backup(backup_type)
            flash('Files backup successfully to D:/ManualBackupDatabase', 'success')
            return redirect('/admin/backup')
        else:
            flash('You do not have the permission to do this action', 'error')
            return redirect('/admin/backup')


@admin_blueprint.route('/offsite_backup',methods=['POST','GET'])
def offsite_backup():
    if request.method == 'POST':
        if AdminModels.is_permission_valid('BACKUP ADMINISTRATOR', 'C'):
            offsite()
            return redirect('/admin/backup')

        else:
            flash('You do not have the permission to do this action', 'error')
            return redirect('/admin/backup')


@admin_blueprint.route('/edit_permission/<role>/<adminid>',methods=['POST','GET'])
def edit_permission(role,adminid):
    print(role,adminid)
    print('ITS WORKIGN!')
    current_admin_role = current_user.adminroles
    print(current_admin_role)
    current_role_type = [roles.type for roles in current_admin_role]
    if 'SYSTEM ADMINISTRATOR' in current_role_type:
        if request.method == 'POST':
            val = request.form.getlist('perm')
            permission = "".join(val)
            admin_role = AdminModels.admin_role
            query = AdminModels.database.session.query(AdminModels.admin_role).filter(and_(AdminModels.admin_role.adminid==adminid,AdminModels.admin_role.type==role)).first()
            print('ITS WORKING X@')
            print(query)
            query.permission = permission
            AdminModels.database.session.commit()
    else:
        abort(403)
    return redirect(url_for('permissions',adminid=adminid))

@admin_blueprint.route('/vuln_search',methods=['POST'])
def vuln_ssearch():
    if request.method == 'POST':
        query = request.form['query']
        response = make_response(redirect(url_for('vuln_search_result',query=query)))
        return response

@admin_blueprint.route('/upgrade/<package>',methods=['POST'])
def upgrade(package):
    if request.method == 'POST':
        subprocess.call('pip install  --upgrade {0}'.format(package), shell=True)
    return redirect('/admin/vulnerability')

@admin_blueprint.route('/upgrade_checked',methods=['POST'])
def upgrade_checked():
    if request.method == 'POST':
        packages = request.form.getlist('package_checked')
        print(packages)
        if len(packages) != 0:
            for package in packages:
                try:
                    subprocess.call('pip install  --upgrade {0}'.format(package), shell=True)
                    # flash('Package successfully upgraded!','success')
                    return redirect('/admin/vulnerability')
                except:
                    continue
        else:
            flash('Please check the box for the desired package you want to update','error')
            return redirect('/admin/vulnerability')

@admin_blueprint.route('/scan',methods=['POST'])
def scan():
    vulners_api = ""
    if not os.getenv('IS_PROD'):
        vulners_api = vulners.Vulners(Configuration.vulners_api)
    vul_dict = {}
    package_dict = {}
    if os.stat('outdated.txt').st_size != 0:
        with open('outdated.txt', 'r') as line:
            next(line)
            next(line)
            for lines in line:
                package_dict[lines.split()[0]] = {'Current_Version': lines.split()[1],
                                                  'Latest_Version': lines.split()[2],
                                                  'PackageName': lines.split()[0]}

    print('reached?')
    for key in package_dict:
        print('reached?')
        results = vulners_api.softwareVulnerabilities(key,package_dict[key]['Current_Version'])
        print(key)
        print(package_dict[key]['Current_Version'])
        print(results)
        if results:
            if results.get('software'):
                Message = " " + results['software'][0]['description'] + results['software'][0]['title']
                cvss = results['software'][0]['cvss']['score']
                cve = results['software'][0]['cvelist'][0]
                print(Message)
            elif results.get('NVD'):
                Message = "" + results['NVD'][0]['description']
                cvss = results['NVD'][0]['cvss']['score']
                cve = results['NVD'][0]['cvelist'][0]
            info = {'Message': Message, 'score': cvss, 'cvelist': cve,'Version':package_dict[key]['Current_Version'],'Latest':package_dict[key]['Latest_Version']}
            vul_dict[key] = info
            print(info)
    if vul_dict:
        message = ''
        for key in vul_dict:
            message +=f'Package Name: {key}\n'
            message += f"Message: {vul_dict[key]['Message']}  \nScore: {vul_dict[key]['score']}\nCVELIST: {vul_dict[key]['cvelist']}"
        construct_email(message)
        flash("Scan completed. Please check your email.",'success')
        return redirect('/admin/vulnerability')
    else:
        message = 'No vulnerability found. Good Job1'
        construct_email(message)
        flash("Scan completed. Please check your email.",'success')
        return redirect('/admin')


def construct_email(message):
    msg = MIMEText(message)
    msg['Subject'] = 'Dependency Check Result'
    msg['From'] = 'piethonlee123@gmail.com'
    msg['To'] = 'piethonlee123@gmail.com'
    send_email(msg)


def send_email(message):
    smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    smtpObj.ehlo()
    smtpObj.starttls()
    smtpObj.ehlo()
    smtpObj.login('pycharming123@gmail.com', 'ASPJPYTHON123')
    smtpObj.sendmail('pycharming123@gmail.com','pycharming123@gmail.com',message.as_string())

def code_backup(keyword):
    if keyword == 'Source Code':
        utils.source_code_backup("noobProgrammer35/ISPJ_BANKING", match=".*\.[p][y]$")
    elif keyword == "HTML files":
        utils.source_code_backup("noobProgrammer35/ISPJ_BANKING", match=".*\.[h][t][m][l]$")
    elif keyword == 'Full Backup':
        utils.source_code_backup('noobProgrammer35/ISPJ_BANKING')
    return redirect(url_for('admin.index'))

def offsite():

    dir = request.form.get('dir')
    if 'files[]' not in request.files:
        flash('No file part')
        return redirect(request.url)
    files = request.files.getlist('files[]')
    for file in files:
        if utils.allowed_file(file.filename):
            print(dir)
            print(secure_filename(file.filename))
            file_name = secure_filename(file.filename)
            file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], file_name))
            path = "static\\upload\\{0}".format(file_name)
            if not os.environ.get('IS_PROD'):
                response = classification.inspect_file("seismic-helper-301408",path,["STREET_ADDRESS","SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER","CREDIT_CARD_NUMBER"],0)
                print(response.result.findings)
                if response.result.findings == []:
                    utils.upload_to_s3("ispj-bucket", 'static/upload/{0}'.format(file_name), dir)
                    flash('Files backup successfully to S3 AMAZON', 'success')
                else:
                    findings = [finding.info_type.name for finding in response.result.findings]
                    flash(f"We detected that the file containing sensitive information such as {findings}","error")
            else:
                utils.upload_to_s3("ispj-bucket", 'static/upload/{0}'.format(file_name), dir)
                flash('Files backup successfully to S3 AMAZON', 'success')
        else:
            flash("This file is not allowed!",'error')


def is_permission_valid(role_1,role_2,permission):
    datadict = {}
    temp = []
    current_admin_id = current_user.adminid
    query = AdminModels.admin_roles.query.join(AdminModels.Administrator).join(AdminModels.roles).filter(
        AdminModels.admin_roles.adminid == current_admin_id and AdminModels.admin_roles.roleid == AdminModels.roles.roleid).all()
    rol = [i.roleid for i in query]
    perm = [i.permission for i in query]
    for i in range(len(rol)):
        datadict[rol[i]] = perm[i]
    if role_1 in datadict:
        return True
    elif role_2 in datadict:
        perm = datadict[role_2]
        print(perm)
        temp.append(perm)
        if permission in temp:
            return True
        else:
            return False
    else:
        return False

