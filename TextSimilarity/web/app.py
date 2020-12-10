from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["users"]

RESPONSE_LIST = {
    "200": {
        "status": 200,
        "message": "Success"
    },
    "301": {
        "status": 301,
        "message": "This username exists"
    },
    "302": {
        "status": 302,
        "message": "Invalid username/password"
    },
    "303": {
        "status": 303,
        "message": "Out of token"
    }
}


def user_exists(usr):
    """
    Check if username exist in the database
    :param usr:
    :return: bool
    """
    return True if users.find({"username": usr}).count() != 0 else False


def verify_password(usr, pwd):
    """
    Check for verification of the password
    :param usr:
    :param pwd:
    :return: bool
    """
    hashed_pw = users.find({"username": usr})[0]["password"]
    return True if bcrypt.hashpw(pwd.encode('utf8'), hashed_pw) == hashed_pw else False


def count_tokens(usr):
    """
    Retrieve the number of tokens
    :param usr:
    :return: number
    """
    return users.find({"username": usr})[0]["tokens"]


class Register(Resource):
    """
        Register new users
        :param
            username
            password
    """

    @staticmethod
    def post():
        req_json = request.get_json()
        username = req_json["username"]
        password = req_json["password"]

        if user_exists(username):
            return jsonify(RESPONSE_LIST["301"])

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        users.insert({
            "username": username,
            "password": hashed_pw,
            "sentence": "",
            "tokens": 10
        })

        return jsonify(RESPONSE_LIST["200"])


class Detect(Resource):
    """
    Detect the similarity of sentences
    """

    @staticmethod
    def post():
        req_json = request.get_json()
        username = req_json["username"]
        password = req_json["password"]
        text1 = req_json["text1"]
        text2 = req_json["text2"]

        if not user_exists(username):
            return jsonify(RESPONSE_LIST["301"])

        if not verify_password(username, password):
            return jsonify(RESPONSE_LIST["302"])

        if count_tokens(username) <= 0:
            return jsonify(RESPONSE_LIST["303"])

        model = spacy.load('en_core_web_sm')
        ratio = model(text1).similarity(model(text2))
        ret_json = {
            "status": 200,
            "similarity": ratio,
            "message": "similarity ratio is calculated"
        }

        users.update({
            "username": username
        }, {
            "$set": {
                "tokens": count_tokens(username) - 1
            }
        })
        return jsonify(ret_json)
api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')

if __name__=="__main__":
    app.run(host='0.0.0.0')