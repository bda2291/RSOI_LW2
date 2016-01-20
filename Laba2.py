import os
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4
from flask import Flask, render_template, redirect, jsonify, flash, request, url_for
from flask_bootstrap import Bootstrap
from flask_login import login_user, current_user, UserMixin, LoginManager
from flask_moment import Moment
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import Form
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'DB.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

manager = Manager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    client_id = db.Column(db.String(256), unique=True, default=sha256(str(uuid4()).encode('UTF-8')).hexdigest())
    client_secret = db.Column(db.String(256), unique=True, default=sha256(str(uuid4()).encode('UTF-8')).hexdigest())
    redirect_uri = db.Column(db.String(128), default='http://localhost:5000/')
    code = db.Column(db.String(128), default=None)
    access_token = db.Column(db.String(128), default=None)
    refresh_token = db.Column(db.String(128), default=None)
    expire_time = db.Column(db.DateTime, default=None)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

class Function(db.Model):
    __tablename__ = 'functions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    semantics = db.relationship('Semantic', backref='function', lazy='dynamic')

    def __repr__(self):
        return '<Function %r>' % self.name

    def to_json_for_semantics(self):
        json_function = {
            'function_id': self.id,
            'function_name': self.name,
        }
        return json_function

    def to_json_for_functions(self):
        semantics = Semantic.query.filter_by(function_id=self.id).all()
        json_function = {
            'function_id': self.id,
            'function_name': self.name,
            'semantics': [Semantic.to_json_for_authors() for semantic in semantics],
        }
        return json_function

class Semantic(db.Model):
    __tablename__ = 'semantics'
    id = db.Column(db.Integer, primary_key=True)
    semantic = db.Column(db.String(1024), unique=True, index=True)
    function_id = db.Column(db.Integer, db.ForeignKey('functions.id'))
    time = db.Column(db.Integer, index=True, default=datetime.utcnow())

    def __repr__(self):
        return '<Semantic %r>' % self.semantic

    def to_json_for_semantics(self):
        r = Function.query.filter_by(id=self.function_id).first()
        json_semantic = {
            'semantic': self.semantic,
            'function_id': self.function_id,
            'function_name': r.name,
        }
        return json_semantic

    def to_json_for_functions(self):
        json_semantic = {
            'semantic': self.semantic,
            'semantic_id': self.id,
        }
        return json_semantic

    @staticmethod
    def from_json(json_post):
        semantic = json_post.get('semantic')
        function = json_post.get('function')
        if (semantic is None or semantic == '') or (function is None or function == ''):
            return Semantic(semantic=None)
        r = Function.query.filter_by(name=function).first()
        if r is None:
            r = Function(name=function)
            return Semantic(semantic=semantic, function=r)
        else:
            return Semantic(Semantic=Semantic, function_id=r.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

@app.route('/', methods=['GET', 'POST'])
def main_page():
        return "Sample Text"

@app.route('/oauth/authorize', methods=['GET'])
def authorize_form():
    response_type = request.args.get('response_type', None)
    client_id = request.args.get('client_id', None)
    state = request.args.get('state', None)

    if client_id is None:
        return render_template('fail.html', reason='require client_id.')

    u = User.query.filter_by(client_id=client_id).first()
    if u is None:
        return render_template('fail.html', reason='client_id is invalid.')

    if response_type is None:
        return redirect(u.redirect_uri + '?error=invalid_request' +
                        ('' if state is None else '&state=' + state), code=302)
    if response_type != 'code':
        return redirect(u.redirect_uri + '?error=unsupported_response_type' +
                        ('' if state is None else '&state=' + state), code=302)
    if current_user.is_authenticated:
        if str(u.client_id) == str(client_id):
            code = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
            u.code = str(code)
            db.session.add(u)
            return redirect(u.redirect_uri + '?code=' + code + ('' if state is None else '&state=' + state),
                            code=302)
        return redirect(u.redirect_uri + '?error=access_denied' + ('' if state is None else '&state=' + state),
                        code=302)
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/oauth/authorize', methods=['POST'])
def authorize():
    form = LoginForm()
    x = request.args.get('client_id', None)
    state = request.args.get('state', None)
    if x is None:
        return render_template('fail.html', reason='require client_id.')
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            if str(user.client_id) == str(x):
                code = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
                user.code = str(code)
                db.session.add(user)
                return redirect(user.redirect_uri + '?code=' + code + ('' if state is None else '&state=' + state),
                                code=302)
            return redirect(user.redirect_uri + '?error=access_denied' + ('' if state is None else '&state=' + state),
                            code=302)
        flash('Invalid email or password.')
    return render_template('login.html', form=form)

@app.route('/oauth/token', methods=['POST'])
def token():
    try:
        grant_type = request.args.get('grant_type', None)
        client_id = request.args.get('client_id', None)
        client_secret = request.args.get('client_secret', None)
    except KeyError:
        return jsonify({'error': 'invalid_request!!!'}), 400

    if client_id is None:
        return jsonify({'error': 'invalid_request'}), 400

    u = User.query.filter_by(client_id=client_id).first()

    if u is None:
        return jsonify({'error': 'invalid_client'}), 400

    if str(u.client_secret) != str(client_secret):
        return jsonify({'error': 'invalid_request'}), 400

    if grant_type == 'authorization_code':
        code = request.args.get('code', None)
        if code is None:
            return jsonify({'error': 'invalid_request'}), 400
        if str(u.code) != str(code):
            return jsonify({'error': 'invalid_grant'}), 400
        u.code = None
        db.session.add(u)
    elif grant_type == 'refresh_token':
        refresh_token = request.args.get('refresh_token', None)
        if refresh_token is None:
            return jsonify({'error': 'invalid_request'}), 400
        if str(u.refresh_token) != str(refresh_token):
            return jsonify({'error': 'invalid_grant'}), 400
        u.refresh_token = None
        db.session.add(u)
    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400
    access_token = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    expire_time = datetime.now() + timedelta(days=365)
    refresh_token = sha256(str(uuid4()).encode('UTF-8')).hexdigest()
    u.access_token = access_token
    u.expire_time = expire_time
    u.refresh_token = refresh_token
    db.session.add(u)
    db.session.commit()
    return jsonify({
        'access_token': access_token,
        'token_type': 'bearer',
        'expires_in': 3600,
        'refresh_token': refresh_token}), 200, {
               'Cache-Control': 'no-store',
               'Pragma': 'no-cache',
           }

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('index'))
        flash('Invalid email or password.')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        flash('You can now login.')
    return render_template('register.html', form=form)

@app.route('/me')
def me():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if (u is None or u.expire_time < datetime.now()) and not current_user.is_authenticated:
        return jsonify({
            'you are': 'stranger'
        })
    return jsonify({
        'email': u.email,
        'you are': u.username
    })

@app.route('/semantics/', methods=['GET'])
def get_semantics():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    page = request.args.get('page', 1, type=int)
    pagination = Semantic.query.paginate(page, per_page=10, error_out=True)
    semantics = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('get_semantics', page=page - 1, _external=True)
    next = None
    if pagination.has_next:
        next = url_for('get_semantics', page=page + 1, _external=True)
    items_on_page = 0
    for item in pagination.items:
        items_on_page += 1
    return jsonify({
        'items_on_page': items_on_page,
        'total_items': pagination.total,
        'page_number': pagination.page,
        'total_pages': pagination.pages,
        'prev': prev,
        'next': next,
        'semantics': [semantic.to_json_for_semantics() for semantic in semantics]
    })

@app.route('/functions/', methods=['GET'])
def get_functions():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    page = request.args.get('page', 1, type=int)
    pagination = Function.query.paginate(page, per_page=10, error_out=True)
    functions = pagination.items
    prev = None
    if pagination.has_prev:
        prev = url_for('get_functions', page=page - 1, _external=True)
    next = None
    if pagination.has_next:
        next = url_for('get_functions', page=page + 1, _external=True)
    items_on_page = 0
    for item in pagination.items:
        items_on_page += 1
    return jsonify({
        'items_on_page': items_on_page,
        'total_items': pagination.total,
        'page_number': pagination.page,
        'total_pages': pagination.pages,
        'prev': prev,
        'next': next,
        'functions': [function.to_json_for_semantics() for function in functions],
    })

@app.route('/semantics/<int:id>', methods=['GET'])
def get_semantic(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    semantic = Semantic.query.get_or_404(id)
    return jsonify(semantic.to_json_for_semantics())

@app.route('/semantics/', methods=['POST'])
def new_semantic():
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    semantic = Semantic.from_json(request.json)
    find_users = Semantic.query.filter_by(semantic=semantic.semantic).first()
    if find_users is None:
        if semantic.semantic is None:
            return jsonify({'error': 'Name or Function are lost'}), 400
        db.session.add(semantic)
        db.session.commit()
        return jsonify(semantic.to_json_for_semantics()), 201
    else:
        return jsonify({'error': 'Same semantic exists'}), 409

@app.route('/functions/<int:id>', methods=['PUT'])
def edit_function(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    function = Function.query.get_or_404(id)
    function.name = request.json.get('function', function.name)
    functions = Function.query.filter_by(name=function.name).first()
    if functions is None and (function.name != '' and function.name is not None):
        db.session.add(function)
        return jsonify(function.to_json_for_semantics())
    else:
        return jsonify({'error': 'Same function exists'}), 409

@app.route('/functions/<int:id>', methods=['DELETE'])
def delete_function(id):
    access_token = request.headers.get('Authorization', '')[len('Bearer '):]
    u = User.query.filter_by(access_token=access_token).first()
    if u is None or u.expire_time < datetime.now():
        return '', 403
    function = Function.query.get_or_404(id)
    if function is None:
        return '', 404
    else:
        q = Semantic.query.filter_by(function_id=function.id).first()
        while q is not None:
            db.session.delete(q)
            db.session.commit()
            q = Semantic.query.filter_by(function_id=function.id).first()
        db.session.delete(function)
        db.session.commit()
        return '', 410

if __name__ == '__main__':
    manager.run()