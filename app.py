# -*- encoding:utf-8 -*-

# !usr/bin/env python
import os
from datetime import datetime
from flask import Flask, jsonify, abort, make_response, request, g, url_for
from flask_sqlalchemy import SQLAlchemy as SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fuck u fuck me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
auth = HTTPBasicAuth()


def make_shell_context():
    return dict(app=app, db=db, User=User, Star=Star, Article=Article,
                Author=Author)


manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


class Catagory:
    NEWPOEM = 0x01
    OLDPOEM = 0x02
    TRANSPOEM = 0x03
    FOREIGNPOEM = 0x04


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    tel = db.Column(db.Integer, unique=True)
    created_articles = db.relationship('Article', backref='user', lazy='dynamic')
    stars_articles = db.relationship('Star', backref='user', lazy='dynamic')

    # albums = db.relationship('Album', backref='user', lazy='dynamic')

    #    @property
    #    def password(self):
    #        raise AttributeError('password is not a readable attribute')

    #    @password.setter
    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})


    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = User.query.get(data['id'])
        return user


# class Album(db.Model):
#     __tablename__ = 'albums'
#     id = db.Column(db.Integer, primary_key=True)
#     album_name = db.Column(db.String(32), index=True)
#     articles = db.relationship('Article', backref='album', lazy='dynamic')
#     created_user_id = db.Column(db.Integer, ForeignKey('user.id'))

class Star(db.Model):
    __tablename__ = 'stars'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    article = db.relationship('Article', uselist=False, backref='star')


class Article(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key=True)
    # album_id = db.Column(db.Integer, db.ForeignKey('albums.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('authors.id'))
    star_id = db.Column(db.Integer, db.ForeignKey('stars.id'))
    catagory = db.Column(db.Integer, index=True)
    stars_num = db.Column(db.Integer)
    title = db.Column(db.String(32))
    body = db.Column(db.Text)
    created_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def to_json(self):
        json_article = {
            'author_id': self.author_id,
            'catagory': self.catagory,
            'stars_num': self.stars_num,
            'title': self.title,
            'body': self.body
        }
        return json_article

        # def __repr__(self):
        #     return '<User %r>' % self.title


class Author(db.Model):
    __tablename__ = 'authors'
    id = db.Column(db.Integer, primary_key=True)
    author_name = db.Column(db.String(32), index=True)
    description = db.Column(db.Text)
    articles = db.relationship('Article', backref='author', lazy='dynamic')

    def to_json(self):
        json_author = {
            'author_name': self.author_name,
            'description': self.description,
            'articles': self.articles
        }
        return json_author


@auth.verify_password
def verify_password(username_or_token, password):
    print("liubing:" + username_or_token)
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/v1.0/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(400)
    else:
        g.user = user
        token = g.user.generate_auth_token(600)
        return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/v1.0/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username=username).first() is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'username': user.username}), 201, {'Location': url_for('get_user', id=user.id, _external=True)}


@app.route('/api/v1.0/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/v1.0/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@app.route('/api/v1.0/articles', methods=['GET'])
@auth.login_required
def get_articles():
    articles = Article.query.all()
    return jsonify({'articles': [article.to_json() for article in articles]})


@app.route('/api/v1.0/articles/<int:article_id>', methods=['GET'])
@auth.login_required
def get_article(article_id):
    article = filter(lambda t: t['id'] == article_id, articles)
    if len(article) == 0:
        abort(404)
    return jsonify({'article': article[0]})


@app.route('/api/v1.0/articles', methods=['POST'])
@auth.login_required
def create_article():
    if not request.json or not 'title' in request.json:
        abort(400)
    article = {
        'id': articles[-1]['id'] + 1,
        'title': request.json['title'],
        'description': request.json.get('description', ""),
        'done': False
    }
    articles.append(article)
    return jsonify({'article': article}), 201


@app.route('/api/v1.0/articles/<int:article_id>', methods=['PUT'])
@auth.login_required
def update_article(article_id):
    article = filter(lambda t: t['id'] == article_id, articles)
    if len(article) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'title' in request.json and type(request.json['title']) != unicode:
        abort(400)
    if 'description' in request.json and type(request.json['description']) != unicode:
        abort(400)
    if 'done' in request.json and type(request.json['done']) != unicode:
        abort(400)
    article[0]['title'] = request.json.get('title', article[0]['title'])
    article[0]['description'] = request.json.get('description', article[0]['description'])
    article[0]['done'] = request.json.get('done', article[0]['done'])
    return jsonify({'article': article[0]})


@app.route('/api/v1.0/articles/<int:article_id>', methods=['DELETE'])
@auth.login_required
def delete_article(article_id):
    article = filter(lambda t: t['id'] == article_id, articles)
    if len(article) == 0:
        abort(404)
    articles.remove(article[0])
    return jsonify({'result': True})


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


def make_public_article(articles):
    new_articles = {}
    for field in articles:
        if field == 'id':
            new_articles['url'] = url_for('get_article', article_id=articles['id'], _external=True)
        else:
            new_articles[field] = field
    return new_articles


if __name__ == '__main__':
    manager.run()
