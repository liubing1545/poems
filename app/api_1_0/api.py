# -*- encoding:utf-8 -*-
# !usr/bin/env python

from flask import jsonify, abort, make_response, request, g, url_for
from flask_httpauth import HTTPBasicAuth
from . import api
from ..models import User, Article
from .. import db

auth = HTTPBasicAuth()

articles = [];

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


@api.route('/api/v1.0/login', methods=['POST'])
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


@api.route('/api/v1.0/users', methods=['POST'])
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


@api.route('/api/v1.0/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@api.route('/api/v1.0/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@api.route('/api/v1.0/articles', methods=['GET'])
@auth.login_required
def get_articles():
    articles = Article.query.all()
    return jsonify({'articles': [article.to_json() for article in articles]})


@api.route('/api/v1.0/articles/<int:article_id>', methods=['GET'])
@auth.login_required
def get_article(article_id):
    article = filter(lambda t: t['id'] == article_id, articles)
    if len(article) == 0:
        abort(404)
    return jsonify({'article': article[0]})


@api.route('/api/v1.0/articles', methods=['POST'])
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


@api.route('/api/v1.0/articles/<int:article_id>', methods=['PUT'])
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


@api.route('/api/v1.0/articles/<int:article_id>', methods=['DELETE'])
@auth.login_required
def delete_article(article_id):
    article = filter(lambda t: t['id'] == article_id, articles)
    if len(article) == 0:
        abort(404)
    articles.remove(article[0])
    return jsonify({'result': True})


@api.errorhandler(404)
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

