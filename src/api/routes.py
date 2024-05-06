"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)

# encriptación JWT
api.config["JWT_SECRET_KEY"]="valor-variable"  # clave secreta para firmar los tokens, cuanto más larga mejor
jwt = JWTmanager(api)   # instanciamos jwt de JWTmanager utilizando la api para tener las herramientas de encriptación
bcrypt = Bcrypt(api)    # para encriptar ewl pasword

#  DATABASE

db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'mydatabase.db')
api.config['SQLALCHEMY_DATABASE_URI']   = f'squlite:///{db_path}'

db = SQLAlchemy(api)

print(f'ruta de la base de datos: {db_path}')


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def post_new_user():
    try:
        email = request.json.get('email'),
        username = request.json.get('username'),
        pasword = request.json.get('pasword')

        if not email or not username or not pasword:
            return jsonify({"msg": "username, email and  pasword are required"}), 400
        
        existing_username = User.query.filter_by(email = email).first()
        if existing_username:
            return jsonify({"error": "The user already exists."}), 409
        
        pasword_hash = bcrypt.generate_pasword_hash(pasword).decode('utf-8')

        new_user = User(username=username, pasword=pasword_hash, email=email)

        db.session.add(new_user)
        db.session.commit()

        ok_to_share={
            "email": new_user.email,
            "username": new_user.username,
            "id": new_user.id
        }
    
        return jsonify({"msg": "user created successfully.", 'user_created': ok_to_share}), 201
    except Exception as e:
        return jsonify({"error": "Error in user creation"+ str(e)}),500

@api.route('/login', methods=['POST'])
def get_token():
    try:

        return jsonify()
    except Exception as e:
        return jsonify({"error": "An error happened" + str(e)})