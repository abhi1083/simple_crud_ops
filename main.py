from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from bson import ObjectId
import bcrypt
import jwt
import ssl
import datetime
from functools import wraps

app = Flask(__name__)
app.config['MONGO_URI'] = "mongodb+srv://db:YjdGMmv3PvQDFx_@cluster0.j523m.mongodb.net/email_templates?retryWrites=true&w=majority"
app.config['SECRET_KEY'] = "c3Fv!kD#8p2@jQrWzT5xV7zZ"
mongo = PyMongo(app, ssl_cert_reqs=ssl.CERT_NONE)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            jwt_payload = jwt.decode(token.split()[1], app.config['SECRET_KEY'], algorithms=['HS256'])
            kwargs['user_email'] = jwt_payload['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    return "Homepage<br> Use /register to register user <br> Use /login to login user<br> Use " \
           "/template to get template<br> Use /template/<template_id> to do 'GET', 'PUT', 'DELETE' methods"


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    user = mongo.db.users.find_one({'email': data['email']})
    if user:
        return jsonify({'message': 'User already registered'}), 409
    mongo.db.users.insert_one({
        'first_name': data['first_name'],
        'last_name': data['last_name'],
        'email': data['email'],
        'password': hashed_pw
    })
    return jsonify({'message': 'User registered successfully!'}), 201


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = mongo.db.users.find_one({'email': auth['email']})
    if user and bcrypt.checkpw(auth['password'].encode('utf-8'), user['password']):
        token = jwt.encode({
            'email': user['email'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/template', methods=['POST'])
@token_required
def create_template(user_email):
    data = request.get_json()
    data['user_email'] = user_email
    inserted_template = mongo.db.templates.insert_one(data)
    inserted_id = str(inserted_template.inserted_id)
    return jsonify({'template_id': inserted_id, 'message': 'Template created successfully'}), 201


@app.route('/template', methods=['GET'])
@token_required
def get_all_templates(user_email):
    templates = list(mongo.db.templates.find({'user_email': user_email}, {'_id': 1}))
    formatted_templates = [{'_id': str(template['_id'])} for template in templates]
    result = []
    for template in formatted_templates:
        template_id = template['_id']
        template_data = mongo.db.templates.find_one({'_id': ObjectId(template_id), 'user_email': user_email}, {'_id': 0})
        if template_data:
            template_data['_id'] = template_id
            result.append(template_data)
    return jsonify(result), 200


@app.route('/template/<template_id>', methods=['GET'])
@token_required
def get_template(user_email, template_id):
    template = mongo.db.templates.find_one({'_id': ObjectId(template_id), 'user_email': user_email}, {'_id': 0})
    if template:
        return jsonify({'template_id': template_id, "template": template}), 200
    else:
        return jsonify({'template_id': template_id, 'message': 'Template not found'}), 404


@app.route('/template/<template_id>', methods=['PUT'])
@token_required
def update_template(user_email, template_id):
    data = request.get_json()
    result = mongo.db.templates.update_one({'_id': ObjectId(template_id), 'user_email': user_email}, {'$set': data})
    print(result)
    if result.modified_count > 0:
        return jsonify({'template_id': template_id, 'message': 'Template updated successfully'}), 200
    else:
        return jsonify({'template_id': template_id, 'message': 'Template not found'}), 404


@app.route('/template/<template_id>', methods=['DELETE'])
@token_required
def delete_template(user_email, template_id):
    result = mongo.db.templates.delete_one({'_id': ObjectId(template_id), 'user_email': user_email})
    if result.deleted_count > 0:
        return jsonify({'template_id': template_id, 'message': 'Template deleted successfully'}), 200
    else:
        return jsonify({'template_id': template_id, 'message': 'Template not found'}), 404


if __name__ == '__main__':
    app.run(debug=True)
