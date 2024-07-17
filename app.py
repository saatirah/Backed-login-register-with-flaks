from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import os
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import timedelta
from flask_jwt_extended import create_access_token, current_user, get_jwt_identity, jwt_required, JWTManager, unset_jwt_cookies
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://21090010:21090010@localhost:27017/21090010?authSource=auth"
app.config["UPLOAD_FOLDER"] = "/home/student/21090083/"
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
jwt = JWTManager(app)
mongo = PyMongo(app)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

class User:
    def __init__(self, email, name, password, age, gender, image_url=None):
        self.email = email
        self.name = name
        self.password = password
        self.age = age
        self.gender = gender
        self.image_url = image_url

    def to_dict(self, include_password=False):
        user_dict = {
            "email": self.email,
            "name": self.name,
            "age": self.age,
            "gender": self.gender,
            "image_url": self.image_url
        }
        if include_password:
            user_dict["password"] = self.password
        return user_dict

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    user = mongo.db.users.find_one({"_id": ObjectId(identity)})
    return user

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    return "Welcome to the User Management API!"

@app.route("/users", methods=['GET'])
@jwt_required()
def get_all_users():
    users = mongo.db.users.find()
    users_list = []
    for user in users:
        user["_id"] = str(user["_id"])
        users_list.append(user)
    return jsonify(users_list), 200

@app.route("/user", methods=['POST', 'PUT', 'DELETE'])
@jwt_required()
def user():
    if request.method == 'POST':
        dataDict = request.get_json()
        email = dataDict["email"]
        name = dataDict["name"]
        password = dataDict["password"]
        age = dataDict["age"]
        gender = dataDict["gender"]
        
        hashed_password = PasswordHasher().hash(password)
        user = User(
            email=email,
            name=name,
            password=hashed_password,
            age=age,
            gender=gender
        )
        mongo.db.users.insert_one(user.to_dict(include_password=True))

        return {
            "message": "Successfully created user",
            "data": f"email: {email}, name: {name}, age: {age}, gender: {gender}"
        }, 200

    elif request.method == 'PUT':
        dataDict = request.get_json()
        user_id = dataDict["id"]
        email = dataDict.get("email")
        name = dataDict.get("name")
        age = dataDict.get("age")
        gender = dataDict.get("gender")

        if not user_id:
            return {
                "message": "ID required"
            }, 400

        update_fields = {}
        if email:
            update_fields["email"] = email
        if name:
            update_fields["name"] = name
        if age:
            update_fields["age"] = age
        if gender:
            update_fields["gender"] = gender

        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update_fields})
        return {
            "message": "Successfully updated user"
        }, 200

    elif request.method == 'DELETE':
        dataDict = request.get_json()
        user_id = dataDict["id"]

        if not user_id:
            return {
                "message": "ID required"
            }, 400

        mongo.db.users.delete_one({"_id": ObjectId(user_id)})
        return {
            "message": "Successfully deleted user"
        }, 200

@app.post('/register')
def signup():
    dataDict = request.get_json()
    name = dataDict["name"]
    email = dataDict["email"]
    password = dataDict["password"]
    re_password = dataDict["re_password"]
    age = dataDict["age"]
    gender = dataDict["gender"]

    if password != re_password:
        return {
            "message": "Passwords do not match!"
        }, 400

    if not email:
        return {
            "message": "Email is required"
        }, 400

    hashed_password = PasswordHasher().hash(password)
    new_user = User(
        email=email,
        name=name,
        password=hashed_password,
        age=age,
        gender=gender
    )
    mongo.db.users.insert_one(new_user.to_dict(include_password=True))

    return {
        "message": "Successfully registered user"
    }, 201

@app.post("/login")
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return {
            "message": "Email and password are required"
        }, 400

    user = mongo.db.users.find_one({"email": email})

    try:
        if not user or not PasswordHasher().verify(user["password"], password):
            return {
                "message": "Invalid email or password"
            }, 400
    except VerifyMismatchError:
        return {
            "message": "Invalid email or password"
        }, 400

    access_token = create_access_token(identity=str(user["_id"]))

    return {
        "token_access": access_token
    }, 200

@app.get("/myprofile")
@jwt_required()
def profile():
    user = current_user

    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "name": user["name"],
        "age": user["age"],
        "gender": user["gender"],
        "image_url": user.get("image_url")
    }

@app.get("/who")
@jwt_required()
def protected():
    return jsonify(
        id=str(current_user["_id"]),
        email=current_user["email"],
        name=current_user["name"],
        age=current_user["age"],
        gender=current_user["gender"],
        image_url=current_user.get("image_url")
    )

@app.get("/whoami")
@jwt_required()
def whoami():
    user_identity = get_jwt_identity()
    user = mongo.db.users.find_one({"_id": ObjectId(user_identity)})
    
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "name": user["name"],
        "age": user["age"],
        "gender": user["gender"],
        "image_url": user.get("image_url")
    }, 200

@app.post("/forgot_password")
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return {
            "message": "Email is required"
        }, 400

    user = mongo.db.users.find_one({"email": email})

    if not user:
        return {
            "message": "User not found"
        }, 404

    # Implement your logic for sending a password reset email here
    # For example, you could generate a token and send it via email

    return {
        "message": "Password reset email sent successfully"
    }, 200

@app.put("/change_password")
@jwt_required()
def change_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not current_password or not new_password:
        return {
            "message": "Current password and new password are required"
        }, 400

    user = current_user

    try:
        if not PasswordHasher().verify(user["password"], current_password):
            return {
                "message": "Current password is incorrect"
            }, 400
    except VerifyMismatchError:
        return {
            "message": "Current password is incorrect"
        }, 400

    hashed_new_password = PasswordHasher().hash(new_password)
    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"password": hashed_new_password}})

    return {
        "message": "Password changed successfully"
    }, 200

@app.put("/change_email")
@jwt_required()
def change_email():
    data = request.json
    new_email = data.get('new_email')

    if not new_email:
        return {
            "message": "New email is required"
        }, 400

    user = current_user

    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"email": new_email}})

    return {
        "message": "Email changed successfully"
    }, 200

@app.post("/logout")
@jwt_required()
def logout():
    resp = jsonify({"logout": True})
    unset_jwt_cookies(resp)
    return resp, 200

@app.post("/upload_image")
@jwt_required()
def upload_image():
    if 'image' not in request.files:
        return {
            "message": "No image part in the request"
        }, 400
    file = request.files['image']
    if file.filename == '':
        return {
            "message": "No image selected for uploading"
        }, 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        
        # Update the user's image URL
        image_url = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        mongo.db.users.update_one({"_id": current_user["_id"]}, {"$set": {"image_url": image_url}})

        return {
            "message": "Image successfully uploaded",
            "image_url": image_url
        }, 200
    else:
        return {
            "message": "Allowed image types are -> png, jpg, jpeg, gif"
        }, 400

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
