from flask_sqlalchemy import SQLAlchemy
from flask import current_app,render_template,Markup,request,flash,redirect
from flask_admin.babel import gettext, ngettext
from hashlib import pbkdf2_hmac
from flask_admin.contrib.sqla import ModelView
from flask_admin.form.upload import ImageUploadField
from flask_admin.helpers import flash_errors,get_redirect_target
from flask_admin import Admin,AdminIndexView,expose,BaseView
from flask_login import LoginManager,current_user, UserMixin,login_user,AnonymousUserMixin
from flask import abort
from wtforms.fields import PasswordField
from wtforms.utils import unset_value
from wtforms import PasswordField,validators
from techmarketplace import utils
import os
import pyotp



database = SQLAlchemy(current_app)
login = LoginManager(current_app)
login.session_protection = None

@login.user_loader
def get_id(adminid):
    return Administrator.query.get(int(adminid))


# admin_role = database.Table('admin_role',database.Column('roleid',database.Integer,database.ForeignKey('roles.roleid'),primary_key=True),database.Column('adminid',database.Integer(),database.ForeignKey('admins.adminid'),primary_key=True))

admin_roles = database.Table('admin_roles',database.Column('type',database.String(50),database.ForeignKey('role.type'),primary_key=True),database.Column('adminid',database.Integer(),database.ForeignKey('admins.adminid'),primary_key=True))


# class admin_roles(database.Model):
#     __tablename__ = 'admin_role'
#     __table_args__ = {'extend_existing': True}
#     roleid = database.Column(database.Integer,database.ForeignKey('roles.roleid'),primary_key=True)
#     adminid = database.Column(database.Integer(),database.ForeignKey('admins.adminid'),primary_key=True)
#     permission = database.Column(database.String(45))

class admin_role(database.Model):
    __tablename__ = 'admin_roles'
    __table_args__ = {'extend_existing': True}
    type = database.Column(database.String(50),database.ForeignKey('role.type'),primary_key=True)
    adminid = database.Column(database.Integer(),database.ForeignKey('admins.adminid'),primary_key=True)
    permission = database.Column(database.String(45))


class roles(database.Model):
    roleid = database.Column(database.Integer,primary_key=True)
    type = database.Column(database.String(30))



    def __init__(self,type):
        self.type = type

    def set_roleid(self,roleid):
        self.roleid = roleid

    def __repr__(self):
        return "<Role %r>" % self.roleid


class role(database.Model):
    __tablename__= "role"
    type = database.Column(database.String(50),primary_key=True)



    def __init__(self,type):
        self.type = type

    def set_roleid(self,roleid):
        self.roleid = roleid

    def __repr__(self):
        return  self.type





#
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

class Customer(database.Model):
    __tablename__ = 'users'
    userid = database.Column(database.Integer,primary_key=True)
    username = database.Column(database.String(50), unique=True)
    fname = database.Column(database.String(45))
    lname = database.Column(database.String(45))
    contact = database.Column(database.Integer())
    email = database.Column(database.String(45),unique=True)
    password_hash = database.Column(database.Text())
    password_salt = database.Column(database.Text())
    failed_attempt = database.Column(database.Integer())
    failed_login_time = database.Column(database.TIMESTAMP())
    verified = database.Column(database.Boolean)
    account = database.relationship('Account',uselist=False,backref='account',lazy=True)


    def __init__(self,username,fname,lname,contact,email,password,verified):
        self.username = username
        self.fname = fname
        self.lname = lname
        self.contact = contact
        self.email = email
        self.verified = verified
        self.password_salt = self.generate_salt()
        self.password_hash = self.generate_hash(password,self.password_salt)


    def generate_hash(self,plaintext_password,salt):
        password_hash = pbkdf2_hmac(
            'sha256',
            b"%b" % bytes(plaintext_password, 'utf-8'),
            b"%b" % bytes(salt, 'utf-8'),
            10000
        )

    def generate_salt(self):
        salt = os.urandom(16)
        return salt.hex()

    def __repr__(self):
        return self.username


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




#class order
#class booking


class MyModelView(AdminIndexView):
    @expose('/')
    def index(self):
        arg1 = 'Hello'
        return self.render('index.html', arg1=arg1)
    def is_accessible(self):
        return current_user.is_authenticated
    def inaccessible_callback(self, name, **kwargs):
        return abort(404)

admin = Admin(current_app, template_mode='bootstrap3',index_view=MyModelView())


class Administrator(database.Model,UserMixin):
    __tablename__ = 'admins'
    adminid = database.Column(database.Integer(),primary_key=True)
    username = database.Column(database.String(45),unique=True)
    password_hash = database.Column(database.Text())
    password_salt = database.Column(database.Text())
    contact = database.Column(database.Integer())
    otp_secret = database.Column(database.String(16))
    TFA = database.Column(database.Boolean)
    # adminrole = database.relationship('roles',secondary=admin_role,backref=database.backref('admins',lazy='joined'))
    adminroles = database.relationship('role',secondary=admin_roles,backref=database.backref('admins',lazy='joined'))



    def __init__(self,username,password,contact):
        self.username = username
        self.password_salt = self.generate_salt()
        self.password_hash = self.generate_hash(password,self.password_salt)
        self.contact = contact
        self.otp_secret = pyotp.random_base32()
        self.TFA = False

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
        return self.adminid

    def get_totp_url(self):
        return  pyotp.totp.TOTP(self.otp_secret).provisioning_uri(self.username, issuer_name="Google")

    def verify_otp(self,token):
        print('test')
        totp = pyotp.TOTP(self.otp_secret)
        # print(totp.now())
        if token == totp.now():
            return True
        else:
            return False

    def verify_password(self,password):
        return password == self.password_hash

    def __repr__(self):
        return "<admin %r>" % self.adminid

    @property
    def Roles(self):
        # query_role = rol.query.join(admin_role).join(Administrator).filter(
        #     admin_role.c.adminid == self.adminid and admin_role.c.roleid == roles.roleid).all()
        query_role = role.query.join(admin_roles).join(Administrator).filter(
             admin_roles.c.adminid == self.adminid and admin_roles.c.roleid == roles.roleid).all()
        return [r.type for r in query_role]

    @property
    def Permissions(self):
        query = admin_role.query.join(role).join(Administrator).filter(admin_roles.c.adminid == self.adminid and admin_roles.c.roleid == roles.roleid).all()
        return [r.permission for r in query]


class CustomerModelView(ModelView):
    column_exclude_list = ('password_salt', 'password_hash','credit_card',"failed_attempt","failed_login_time")
    form_excluded_columns = ('password_hash', 'password_salt',"failed_attempt","failed_login_time")

    def is_accessible(self):
        if current_user.is_authenticated:
            for r in current_user.adminroles:
                if r.type == "USER ADMINISTRATOR":
                    return True


    def inaccessible_callback(self, name, **kwargs):
        return abort(404)

    def edit_form(self, obj=None):
        form = super(CustomerModelView, self).edit_form(obj)
        if is_permission_valid("USER ADMINISTRATOR",'U'):
            return form
        else:
            abort(403)

    def create_form(self, obj=None):
        form = super(CustomerModelView,self).create_form(obj)
        if is_permission_valid('USER ADMINISTRATOR','C'):
            return form
        else:
            abort(403)

    def get_create_form(self):
        form = super(CustomerModelView,self).get_create_form()
        form.password = PasswordField('Password',validators=[validators.DataRequired('Password is required'),validators.Length(min=8,message='Password minimum 8 characters'),validators.Regexp('^.*(?=.{8,10})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$',message='Password must contain at least 8 characters with uppercase,lowercase,symbol and numbers.')])
        return form


    def _on_model_change(self, form, model, is_created):
        if is_created == True:
            p = form.password.data
            salt = utils.generate_salt()
            hash = utils.generate_hash(p, salt)
            user = Customer.query.filter_by(username=form.username.data).first()
            user.password_hash = hash
            user.password_salt = salt
            database.session.commit()


    def delete_model(self, model):
        """
            Delete model.

            :param model:
                Model to delete
        """
        if is_permission_valid('USER ADMINISTRATOR','D'):

            try:
                self.on_model_delete(model)
                self.session.flush()
                self.session.delete(model)
                self.session.commit()
            except Exception as ex:
                flash(gettext('You cannot delete user who has an account or has transaction history. '),'error')
                self.session.rollback()

                return False
            else:
                self.after_model_delete(model)

            return True
        else:
            flash(gettext('You do not have the permission to delete'), 'error')

# class ProductModelView(ModelView):
#
#     create_template = 'product_create.html'
#     edit_template = 'edit_product.html'
#     def my_formatter(view,context,model,name):
#         if model.Image:
#             Image = "<img src ='../../static/upload/%s' height='100px' width='100px'>" % (model.Image)
#             return Markup(Image)
#
#     def _formatter(view, context, model, name):
#         if model.Image2:
#             Image = "<img src ='../../static/upload/%s' height='100px' width='100px'>" % (model.Image2)
#             return Markup(Image)
#
#     @expose('/edit/', methods=['GET', 'POST'])
#     def edit_view(self):
#         id = request.args.get('id')
#         self._template_args['product'] = Product.query.filter_by(productid=id).first()
#         return super(ProductModelView, self).edit_view()
#
#     column_formatters = dict(Image=my_formatter,Image2=_formatter)
#
#
#     def is_accessible(self):
#         if current_user.is_authenticated:
#             current_admin_id = current_user.adminid
#             # meaning of query_role
#             # select * from roles inner join admin_role
#             # on adnmin_role,roleid = roles.roleid inner join Admin a on a.adminid = admin_role.adminid
#             query_role = roles.query.join(admin_role).join(Admin).filter(admin_role.c.adminid == current_admin_id and admin_role.c.roleid == roles.roleid).all()
#             print(query_role)
#             for role in query_role:
#                 print(role.type)
#                 if role.type == 'Super' or role.type == 'Inventory Administrator':
#                     return True
#
#     def inaccessible_callback(self, name, **kwargs):
#         return abort(404)


class BackupView(BaseView):
    @expose('/')
    def index(self):
        table_names = database.engine.table_names()
        return self.render('backup.html',table_names = table_names)

    def is_accessible(self):
        if current_user.is_authenticated:
            for r in current_user.adminroles:
                if r.type == "BACKUP ADMINISTRATOR":
                    return True

    def inaccessible_callback(self, name, **kwargs):
        return abort(404)

class VulnerabilityView(BaseView):
    @expose('/')
    def index(self):
        print(current_user.adminroles)
        package_version_dict = utils.library_installed()
        package_dict = utils.outdated_version()
        print(package_dict)
        return self.render('vulnerability.html',package_version_dict=package_version_dict,package_dict=package_dict)

    # def is_accessible(self):
    #     if current_user.is_authenticated:
    #         query_role = roles.query.join(admin_role).join(Administrator).filter(
    #             admin_role.c.adminid == current_user.adminid and admin_role.c.roleid == roles.roleid).all()
    #         print(admin_role.c)
    #         for role in query_role:
    #             if role.type == 'System Administrator':
    #                 return True

class AdministratorModelView(ModelView):


    column_list = {'username','Roles','adminid','contact','Configure Permission','Permissions'}
    column_exclude_list = ('password_salt', 'password_hash','otp_secret','TFA')
    form_excluded_columns = ('password_hash', 'password_salt','otp_secret','TFA')

    def is_accessible(self):
        if current_user.is_authenticated:
            for r in current_user.adminroles:
                if r.type == 'SYSTEM ADMINISTRATOR':
                    return True
        # if current_user.is_authenticated:
        #     current_admin_id = current_user.adminid
        #     query_role = roles.query.join(admin_role).join(Administrator).filter(admin_role.c.adminid == current_admin_id and admin_role.c.roleid == roles.roleid).all()
        #     query = Administrator.query.join(admin_role).join(roles).filter(admin_role.c.adminid == current_admin_id and admin_role.c.roleid == roles.roleid).first()
        #     test = database.session.query(admin_role.c.adminid).join(Administrator).join(roles).filter(admin_role.c.adminid == current_admin_id and admin_role.c.roleid == roles.roleid).all()
        #
        #     print('===========================')
        #     print(test)
        #     # understanding adminrole variable or backref
        #     testref = current_user.adminrole
        #     print([i.type for i in testref])
        #     # for i in query:
        #     #     print(i.roleid)
        #     print('==============================')
        #     for role in query_role:
        #         print(role.type)
        #         if role.type == 'System Administrator':
        #             return True

    def get_create_form(self):
        # original form provided by flask admin
        form = super(AdministratorModelView,self).get_create_form()
        form.password = PasswordField('Password',validators=[validators.DataRequired('Password is required'),validators.Length(min=8,message='Password minimum 8 characters'),validators.Regexp('^.*(?=.{8,10})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$',message='Password must contain at least 8 characters with uppercase,lowercase,symbol and numbers.')])

        return form

    def get_edit_form(self):
        form = super(AdministratorModelView,self).get_edit_form()
        print('==-=--=-=------------------------------------------------------------')


        return form


    def edit_form(self, obj=None):
        form = super(AdministratorModelView,self).edit_form(obj)
        form.password2 = PasswordField('Password', validators=[validators.Length(min=8,message='Password minimum 8 characters'),validators.Regexp('^.*(?=.{8,10})(?=.*[a-zA-Z])(?=.*?[A-Z])(?=.*\d)[a-zA-Z0-9!@£$%^&*()_+={}?:~\[\]]+$',message='Password must contain at least 8 characters with uppercase,lowercase,symbol and numbers.')])

        return form

    def _formatter(view, context, model, name):

        t = model.adminid

        _html = f'<a href ="/permissions/{t}">Edit Permission</a>'
        return Markup(_html)

    column_formatters = {'Configure Permission':_formatter}

    # def create_form(self, obj=None):
    #     # action original by flask admin
    #     form = super(AdministratorModelView,self).create_form(obj)
    #     print('fucl')
    #     return form

    def _on_model_change(self, form, model, is_created):
        if is_created == True:
            password = form.password.data
            salt = utils.generate_salt()
            hash = utils.generate_hash(password,salt)
            admin = Administrator.query.filter_by(username=form.username.data).first()
            admin.password_salt = salt
            admin.password_hash = hash
            admin.otp_secret = pyotp.random_base32()
            database.session.commit()

    def inaccessible_callback(self, name, **kwargs):
        return abort(404)


def is_permission_valid(role_2,permission):
    datadict = {}
    temp = []
    current_admin_id = current_user.adminid
    # role object return
    query = admin_role.query.join(Administrator).join(role).filter(
        admin_role.adminid == current_admin_id and admin_role.type == role.type).all()
    rol = [i.type for i in query]
    perm = [i.permission for i in query]
    print(rol)
    for i in range(len(rol)):
        datadict[rol[i]] = perm[i]
    if role_2 in datadict:
        perm = datadict[role_2]
        print(perm)
        # temp.append(perm)
        if permission in perm:
            return True
        else:
            return False
    else:
        return False



admin.index_view = MyModelView(name='admin')
# admin.add_view(ProductModelView(Product,database.session,endpoint='product'))
admin.add_view(CustomerModelView(Customer,database.session))
admin.add_view(CustomerModelView(Account,database.session))
admin.add_view(BackupView(name='Backup',endpoint='backup'))
admin.add_view(AdministratorModelView(Administrator,database.session))
# admin.add_view(EditPermissionView(name='Edit Permission',endpoint='permission'))
admin.add_view(VulnerabilityView(name='Vulnerability',endpoint='vulnerability'))
