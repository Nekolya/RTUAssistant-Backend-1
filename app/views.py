from app import app
from flask import Flask, flash, request, redirect, url_for, session, jsonify, render_template, make_response
import requests
import jwt
from os import environ 
import datetime

SECRET = environ.get('SECRET')

####
@app.route('/auth/login', methods=["POST", "GET", "OPTIONS"])
def login():
    req = request.get_json(force=True)
    secret = req['secret']
    fingerprint = req['fingerprint']
    status = ""
    user = login(secret)
    
    if user: #if secret exist
        if user.status == 'ok':
            status = 'ok'
            res = {"status": status}
            access_token = jwt.encode({'user_id': user.id, 
                                        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
                                        SECRET, algorithm='HS256')

            refresh_token = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=60)}, 
                                        SECRET, algorithm='HS256')
            
            res['access_token'] = encoded_jwt
            res['refresh_token'] = refresh_token
            user.update({'refresh_token': refresh_token, 'fingerprint': fingerprint})
            db.session.commit()

        elif user.status == 'account_suspended':
            status = 'error'
            error = 'account_suspended'
            res = {"status": status}
            res['error'] = error

    else:
        status = 'error'
        error = 'secret_incorrect'
        res = {"status": status}
        res['error'] = error

    response = jsonify(res)
    return make_response(response)

#############
@app.route('/auth/refresh_token', methods=["POST", "GET", "OPTIONS"])
def refresh_token():
    req = request.get_json(force=True)
    refresh_token = req['refresh_token']
    fingerprint = req['fingerprint']
    status = ""

    try:
        data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
        user_id = data["user_id"]
        user = get_user_by_pk(user_id)
        if user:
            if user.status == 'ok':
                error = user.refresh_allow(refresh_token, fingerprint)
                if error == 'ok':
                    status = 'ok'
                    res = {"status": status}
                    access_token = jwt.encode({'user_id': user.id, 
                                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
                                                SECRET, algorithm='HS256')

                    refresh_token = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=60)}, 
                                                SECRET, algorithm='HS256')
                    
                    res['access_token'] = encoded_jwt
                    res['refresh_token'] = refresh_token
                    user.update({'refresh_token': refresh_token})
                    db.session.commit()
                else:
                    status = 'error'
                    res = {"status": status}
                    res['error'] = error
            elif user.status == 'account_suspended':
                status = 'error'
                error = 'account_suspended'
                res = {"status": status}
                res['error'] = error
        else:
            status = 'error'
            error = 'internal_server_error'
            res = {"status": status}
            res['error'] = error
    # Signature has expired
    except jwt.ExpiredSignatureError:
        status = 'error'
        error = 'token_expired'
        res = {"status": status}
        res['error'] = error
    except jwt.DecodeError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error
    except jwt.InvalidSignatureError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error
    response = jsonify(res)
    return make_response(response)

###
@app.route('/auth/logout', methods=["POST", "GET", "OPTIONS"])
def logout():
    req = request.get_json(force=True)
    refresh_token = req['refresh_token']
    fingerprint = req['fingerprint']
    status = ""

    try:
        data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
        user_id = data["user_id"]
        user = get_user_by_pk(user_id)
        if user:
            if user.status == 'ok':
                error = user.refresh_allow(refresh_token, fingerprint)
                if error == 'ok':
                    status = 'ok'
                    res = {"status": status}
                    refresh_token = jwt.encode({'exp': datetime.datetime.utcnow()}, 
                                                SECRET, algorithm='HS256')
                    
                    user.update({'refresh_token': refresh_token})
                    db.session.commit()
                else:
                    status = 'error'
                    res = {"status": status}
                    res['error'] = error
            elif user.status == 'account_suspended':
                status = 'error'
                error = 'account_suspended'
                res = {"status": status}
                res['error'] = error
        else:
            status = 'error'
            error = 'internal_server_error'
            res = {"status": status}
            res['error'] = error
    # Signature has expired
    except jwt.ExpiredSignatureError:
        status = 'error'
        error = 'token_expired'
        res = {"status": status}
        res['error'] = error
    except jwt.DecodeError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error
    except jwt.InvalidSignatureError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error

    data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
    user_id = data["user_id"]
    user = get_user_by_pk(user_id)
