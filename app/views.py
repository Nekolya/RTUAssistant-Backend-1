from app import app
from flask import Flask, flash, request, redirect, url_for, session, jsonify, render_template, make_response
import requests
import jwt
from os import environ 
from . import get_user_by_pk, user_login


SECRET = environ.get('SECRET')

####
@app.route('/auth/login', methods=["POST", "GET", "OPTIONS"])
def login():
    req = request.get_json(force=True)
    login = req['login']
    passw = req['password']
    fingerprint = req['fingerprint']
    status = ""
    user = user_login(login, passw)
    if user:
        if user.status == 'ok':
            status = 'ok'
            encoded_jwt = jwt.encode({'user_id': user.id}, SECRET, algorithm='HS256')
            res = {"status": status}
            res['access_token'] = encoded_jwt
            res['refresh_token'] = user.refresh_token

        elif user.status == 'account_suspended':
            status = 'error'
            error = 'account_suspended'
            res = {"status": status}
            res['error'] = error

    else:
        status = 'error'
        error = 'login_incorrect'
        res = {"status": status}
        res['error'] = error

    response = jsonify(res)
    return make_response(response)

####
@app.route('/auth/refresh_token', methods=["POST", "GET", "OPTIONS"])
def refresh_token():
    req = request.get_json(force=True)
    refresh_token = req['refresh_token']
    status = ""

    data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
    user_id = data["user_id"]
    #user = bd.get("user_id") if user exist status = ok else 
    res = {"status": status}
    if status == "error":
        error = ""
        res["error"] = error
    
    else:
        access_token = ""
        refresh_token = ""
        res["access_token"] = access_token
        res["refresh_token"] = refresh_token
    response = jsonify(res)
    return make_response(response)


###
@app.route('/auth/logout', methods=["POST", "GET", "OPTIONS"])
def logout():
    #req = request.get_json(force=True)
    #access_token = req['access_token']
    status = ""
    res = {"status": status}
    if status == "error":
        error = ""
        res["error"] = error


@app.route('/')
def mew():
    return 'Mew'
