# Code adapted from the example code given on canvas, and from my own code from assignment 2

from flask import Flask, render_template, request, jsonify, send_file
from google.cloud import datastore, storage

import io
import json
import os
import requests

from six.moves.urllib.request import urlopen # type: ignore
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.urandom(16)

datastore_client = datastore.Client()

# Load Auth0 and Photo Bucket credentials from JSON
with open("docs/credentials.json", "r", encoding="utf-8") as file:
    creds = json.load(file)

DOMAIN = creds.get("DOMAIN")
CLIENT_ID = creds.get("CLIENT_ID")
CLIENT_SECRET = creds.get("CLIENT_SECRET")
PHOTO_BUCKET = creds.get("PHOTO_BUCKET")

if DOMAIN == "\u0000" or CLIENT_ID == "\u0000" or CLIENT_SECRET == "\u0000" or PHOTO_BUCKET == "\u0000":
    raise RuntimeError("Error: Missing required credentials (DOMAIN, CLIENT_ID, CLIENT_SECRET, PHOTO_BUCKET). Please add them to docs/credentials.json.")

# Error messages
ERROR_400 = {"Error": "The request body is invalid"}, 400, {"Content-Type": "application/json"}
ERROR_401 = {"Error": "Unauthorized"}, 401, {"Content-Type": "application/json"}
ERROR_403 = {"Error": "You don't have permission on this resource"}, 403, {"Content-Type": "application/json"}
ERROR_404 = {"Error": "Not found"}, 404, {"Content-Type": "application/json"}
ERROR_409 = {"Error": "Enrollment data is invalid"}, 409, {"Content-Type": "application/json"}

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code, content_type = {"Content-Type": "application/json"}):
        self.error = error
        self.status_code = status_code
        self.content_type = content_type

    def __init__(self, error_object):
        self.error = error_object[0]
        self.status_code = error_object[1]
        self.content_type = error_object[2]

# Error handlers
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError(ERROR_401)
    
    jsonurl = urlopen("https://"+ DOMAIN +"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(ERROR_401)

    if unverified_header["alg"] == "HS256":
        raise AuthError(ERROR_401)

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(ERROR_401)
        except jwt.JWTClaimsError:
            raise AuthError(ERROR_401)
        except Exception:
            raise AuthError(ERROR_401)
        return payload
    else:
        raise AuthError(ERROR_401)

# Same as verify_jwt, but just returns "None" instead of raising an Error
def get_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return None
    
    jsonurl = urlopen("https://"+ DOMAIN +"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        return None

    if unverified_header["alg"] == "HS256":
        return None
    
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except Exception:
            return None
        return payload
    else:
        return None

# Get a user by id if the requester has admin role or is the user with the given id, otherwise return 401 Unauthorized if no JWT or invalid JWT, or 403 Forbidden if valid JWT but not admin and not the user with the given id
@app.route("/users/<int:user_id>", methods=["GET"])
def fetch_user_by_id(user_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Query for all users with role "admin" and get their "sub"
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())
    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    valid_user_id = valid_user[0].key.id

    # If user has admin role, or JWT is owned by user_id in the path parameter
    if (
        payload["sub"] in admin_subs or
        valid_user_id == user_id
    ):
        # Fetch user
        key = datastore_client.key("users", user_id)
        user = datastore_client.get(key)

        # Add the id because it doesn't come with it by default
        user_with_id = dict(user)
        user_with_id["id"] = user_id

        # Add courses if instructor or student
        role = user_with_id["role"]
        if role == "instructor":
            # Query instructor_id in courses
            query = datastore_client.query(kind="courses")
            query.add_filter("instructor_id", "=", user_id)
            courses = list(query.fetch())

            course_ids = []
            for course in courses:
                course_ids.append(course.key.id)
            user_with_id["courses"] = course_ids

        if role == "student":
            # Query student_id in enrollments
            query = datastore_client.query(kind="enrollments")
            query.add_filter("student_id", "=", user_id)
            enrollments = list(query.fetch())

            courses = []
            for enrollment in enrollments:
                courses.append(enrollment["course_id"])

            # Query instructor_id in courses
            query = datastore_client.query(kind="courses")
            query.add_filter("instructor_id", "=", user_id)
            classes_taught = list(query.fetch())

            for class_taught in classes_taught:
                courses.append(class_taught.key.id)

            user_with_id["courses"] = courses

        # 200 OK
        return (
            jsonify(user_with_id),
            200,
            {"Content-Type": "application/json"}
        )
    # 403 Forbidden
    raise AuthError(ERROR_403)

# Get all users if the requester has admin role, otherwise return 401 Unauthorized if no JWT or invalid JWT, or 403 Forbidden if valid JWT but not admin
@app.route("/users", methods=["GET"])
def fetch_all_users():
    # Fetch the payload or lack thereof
    payload = get_jwt(request)
    
    # Query for all users with role "admin" and get their "sub"
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    users = []
    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)
    # If JWT was valid, but not an admin, 403 Forbidden
    elif payload["sub"] not in admin_subs:
        raise AuthError(ERROR_403)
    # Return all users if admin
    else:
        # Fetch the users as an iterator
        query = datastore_client.query(kind="users")
        data = query.fetch()

        for user in data:
            user_with_id = {
                "id": user.key.id,
                "role": user["role"],
                "sub": user["sub"],
            }
            users.append(user_with_id)

    # 200 OK
    return (
        jsonify(users),
        200,
        {"Content-Type": "application/json"}
    )

# Get a user's avatar image if the JWT is owned by the user in the path parameter
@app.route("/users/<int:user_id>/avatar", methods=["GET"])
def fetch_avatar_by_id(user_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())
    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    valid_user_id = valid_user[0].key.id

    # If JWT is owned by user_id in the path parameter
    if (valid_user_id == user_id):
        # Fetch user
        key = datastore_client.key("users", user_id)
        user = datastore_client.get(key)

        # Get public_url from user's avatar_url
        avatar_url = user.get("avatar_url")

        # 404 Not Found
        if not avatar_url:
            raise AuthError(ERROR_404)

        # Look up the profile_image_map entry using the avatar_url
        profile_image_key = datastore_client.key("profile_image_map", avatar_url)
        profile_image_entity = datastore_client.get(profile_image_key)

        # 404 Not Found if no mapping exists
        if not profile_image_entity or "image_url" not in profile_image_entity:
            raise AuthError(ERROR_404)

        public_url = profile_image_entity["image_url"]

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        # Create a blob with the given file name
        file_name = public_url.split("/")[-1]
        blob = bucket.blob(file_name)
        # Create a file object in memory using Python io package
        file_obj = io.BytesIO()
        # Download the file from Cloud Storage to the file_obj variable
        blob.download_to_file(file_obj)
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Send the object as a file in the response with the correct MIME type and file name 
        # 200 OK
        return (
            send_file(file_obj, mimetype='image/x-png', download_name=file_name),
            200
        )
    # 403 Forbidden
    raise AuthError(ERROR_403)

# Get all courses
@app.route("/courses", methods=["GET"])
def get_all_courses():
    # Extract optional query parameters
    offset = request.args.get("offset", type=int)
    limit = request.args.get("limit", type=int)

    # Set defaults if not provided
    if offset is None:
        offset = 0
    if limit is None:
        limit = 3
    
    # Query courses with pagination
    query = datastore_client.query(kind="courses")
    query.order = ["subject"]
    iter = query.fetch(offset=offset, limit=limit)
    courses = []
    for course in iter:
        course_dict = dict(course)
        course_dict["id"] = course.key.id
        course_dict["self"] = request.host_url.rstrip('/') + "/courses/" + str(course.key.id)
        courses.append(course_dict)

    response = {"courses": courses}

    # Check if there are more courses for the next page
    total_courses_query = datastore_client.query(kind="courses")
    total_courses = len(list(total_courses_query.fetch()))
    if offset + limit < total_courses:
        next_offset = offset + limit
        base_url = request.base_url
        response["next"] = base_url + "?offset=" + str(next_offset) + "&limit=" + str(limit)

    # 200 OK
    return (
        jsonify(response),
        200,
        {"Content-Type": "application/json"}
    )

@app.route("/courses/<int:course_id>", methods=["GET"])
def get_course_by_id(course_id):
    # Fetch the course by ID
    key = datastore_client.key("courses", course_id)
    course = datastore_client.get(key)

    # 404 Not Found
    if course is None:
        raise AuthError(ERROR_404)

    course_with_id = dict(course)
    course_with_id["id"] = course_id

    # 200 OK
    return (
        jsonify(course_with_id),
        200,
        {"Content-Type": "application/json"}
    )

# Get the students enrolled in a course with the given course_id if the requester has admin role or is the instructor of the course
@app.route("/courses/<int:course_id>/students", methods=["GET"])
def get_enrollment_by_id(course_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Query for all users with role "admin" and get their "sub"
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())
    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    valid_user_id = valid_user[0].key.id

    # Get the id of the instructor of this course
    key = datastore_client.key("courses", course_id)
    course = datastore_client.get(key)
    if not course or "instructor_id" not in course:
        raise AuthError(ERROR_403)
    instructor_id = course["instructor_id"]

    # If user has admin role, or JWT is owned by the instructor of this course in the path parameter
    if (
        payload["sub"] in admin_subs or
        valid_user_id == instructor_id
    ):
        # Fetch the already existing course
        key = datastore_client.key("courses", course_id)
        course = datastore_client.get(key)

        if course is None:
            # 403 Forbidden
            raise AuthError(ERROR_403)

        # Get students enrolled in the course
        enrollment_query = datastore_client.query(kind="enrollments")
        enrollment_query.add_filter("course_id", "=", course_id)
        enrollments = list(enrollment_query.fetch())
        students = [enrollment["student_id"] for enrollment in enrollments]
            
        # 200 OK
        return (
            students,
            200,
            {"Content-Type": "application/json"}
        )
    # 401 Unauthorized
    raise AuthError(ERROR_403)

# Update a course with the given course_id with the information in the request body if the requester has admin role
@app.route("/courses/<int:course_id>", methods=["PATCH"])
def update_course_by_id(course_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())

    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)

    # Query for all users with role "admin" and get their "sub" value
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    # If user has admin role
    if (payload["sub"] in admin_subs):

        # Fetch the already existing course
        key = datastore_client.key("courses", course_id)
        course = datastore_client.get(key)

        if course is None:
            # 403 Forbidden
            raise AuthError(ERROR_403)
        
        # Get data from request to update the review with
        data = request.get_json()
        subject = data.get("subject")
        number = data.get("number")
        title = data.get("title")
        term = data.get("term")
        instructor_id = data.get("instructor_id")

        # Update review in-place
        if subject:
            course["subject"] = subject
        if number:
            course["number"] = number
        if title:
            course["title"] = title
        if term:
            course["term"] = term
        if instructor_id is not None:
            # Find the instructor with the id given in the request body
            query = datastore_client.query(kind="users")
            query.add_filter("role", "=", "instructor")
            instructor_users = list(query.fetch())
            instructor_ids = [user.key.id for user in instructor_users]

            # 400 Bad Request
            if instructor_id not in instructor_ids:
                raise AuthError(ERROR_400)

            course["instructor_id"] = instructor_id

        # Save the updated review to datastore
        datastore_client.put(course)
            
        # 200 OK
        return (
            course,
            200,
            {"Content-Type": "application/json"}
        )
    # 403 Forbidden
    raise AuthError(ERROR_403)

# Update the enrollment of a course with the given course_id by adding and removing students in the request body if the requester has admin role or is the instructor of the course
@app.route("/courses/<int:course_id>/students", methods=["PATCH"])
def update_enrollment(course_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Query for all users with role "admin" and get their "sub"
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())
    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    valid_user_id = valid_user[0].key.id

    # Get the id of the instructor of this course
    key = datastore_client.key("courses", course_id)
    course = datastore_client.get(key)
    if not course or "instructor_id" not in course:
        raise AuthError(ERROR_403)
    instructor_id = course["instructor_id"]

    # If user has admin role, or JWT is owned by the instructor of this course in the path parameter
    if (
        payload["sub"] in admin_subs or
        valid_user_id == instructor_id
    ):
        # Fetch the already existing course
        key = datastore_client.key("courses", course_id)
        course = datastore_client.get(key)

        if course is None:
            # 403 Forbidden
            raise AuthError(ERROR_403)
        
        # Get data from request to update the enrollment with
        data = request.get_json()
        # These should be lists of student IDs
        students_to_add = data.get("add")
        students_to_remove = data.get("remove")

        # Add all students in students_to_add
        for student_id in students_to_add:
            # Check if student with student_id exists
            key = datastore_client.key("users", student_id)
            student = datastore_client.get(key)
            if not student or student.get("role") != "student":
                raise AuthError(ERROR_409)
            
            # Check if student is in the list to remove
            if student_id in students_to_remove:
                raise AuthError(ERROR_409)

            # Add student to the course by creating an enrollment entity
            # Use course_id|student_id as the primary key so each mapping is unique
            key = datastore_client.key(
                "enrollments",
                f"{course_id}|{student_id}"
            )
            enrollment_entity = datastore.Entity(key=key)
            enrollment_entity.update({
                "course_id": course_id,
                "student_id": student_id
            })
            datastore_client.put(enrollment_entity)

        # Remove all students in students_to_remove
        for student_id in students_to_remove:
            # Check if student with student_id exists
            key = datastore_client.key("users", student_id)
            student = datastore_client.get(key)
            if not student or student.get("role") != "student":
                raise AuthError(ERROR_409)
            
            # No need to check if student is in the list to add

            # Remove student from the course by deleting the enrollment entity
            # Use course_id|student_id as the primary key so each mapping is unique
            key = datastore_client.key(
                "enrollments",
                f"{course_id}|{student_id}"
            )
            enrollment_entity = datastore_client.get(key)
            if enrollment_entity is None:
                continue
            datastore_client.delete(key)
            
        # 200 OK
        return (
            "", # Empty body
            200,
            {"Content-Type": "application/json"}
        )
    # 401 Unauthorized
    raise AuthError(ERROR_403)

# Delete a user's avatar image if the JWT is owned by the user in the path parameter
@app.route("/users/<int:user_id>/avatar", methods=["DELETE"])
def delete_avatar_by_user_id(user_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())
    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    valid_user_id = valid_user[0].key.id

    # If JWT is owned by user_id in the path parameter
    if (valid_user_id == user_id):
        # Fetch user
        key = datastore_client.key("users", user_id)
        user = datastore_client.get(key)

        # Get public_url from user's avatar_url
        avatar_url = user.get("avatar_url")

        # 404 Not Found
        if not avatar_url:
            raise AuthError(ERROR_404)
        
        # Look up the profile_image_map entry using the avatar_url
        profile_image_key = datastore_client.key("profile_image_map", avatar_url)
        profile_image_entity = datastore_client.get(profile_image_key)

        # 404 Not Found if no mapping exists
        if not profile_image_entity or "image_url" not in profile_image_entity:
            raise AuthError(ERROR_404)

        # Delete the user's avatar_url from the user entity
        if "avatar_url" in user:
            del user["avatar_url"]
        datastore_client.put(user)
        # Delete the corresponding profile_image_map
        datastore_client.delete(profile_image_key)

        # Finally, delete the image from Cloud Storage
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        file_name = profile_image_entity["image_url"].split("/")[-1]
        blob = bucket.blob(file_name)
        # Delete the file from Cloud Storage
        try:
            blob.delete()
        except Exception as e:
            # 404 Not Found
            print(f"Error deleting image from storage: {e}")
            raise AuthError(ERROR_404)
        
        # 204 No Content
        return "", 204
    else:
        # 403 Forbidden
        raise AuthError(ERROR_403)

# Delete a course with the given course_id if the requester has admin role
@app.route("/courses/<int:course_id>", methods=["DELETE"])
def delete_course_by_user_id(course_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())

    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    
    # Query for all users with role "admin" and get their "sub" value
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    # If user has admin role
    if (payload["sub"] in admin_subs):
        # Fetch the already existing course
        key = datastore_client.key("courses", course_id)
        course = datastore_client.get(key)

        if course is None:
            # 403 Forbidden
            raise AuthError(ERROR_403)
        
        # Delete the review by its key
        datastore_client.delete(key)

        # 204 No Content
        return "", 204
    else:
        # 403 Forbidden
        raise AuthError(ERROR_403)

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():
    data = request.get_json()

    # 400 Bad Request
    if not data or "username" not in data or "password" not in data:
        raise AuthError(ERROR_400)

    # Get username and password from request
    username = data["username"]
    password = data["password"]

    # Get a JWT from Auth0
    body = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    headers = { "Content-Type": "application/json" }
    url = 'https://' + DOMAIN + '/oauth/token'
    response = requests.post(url, json=body, headers=headers)
    response_json = response.json()
    id_token = response_json.get("id_token")

    if not id_token:
        raise AuthError(ERROR_401)

    # Handle other errors from Auth0
    if response.status_code == 400 in response_json:
        raise AuthError(ERROR_400)
    if response.status_code == 401 or "Error" in response_json:
        raise AuthError(ERROR_401)
    if response.status_code == 403 in response_json:
        raise AuthError(ERROR_403)
    if response.status_code == 404 in response_json:
        raise AuthError(ERROR_404)

    response = {
        "token": id_token
    }

    # 200 OK
    return (
        response, 
        200, 
        {'Content-Type':'application/json'}
    )

# Create or update a user's avatar image with the file sent in the request
@app.route('/users/<int:user_id>/avatar', methods=['POST'])
def create_or_update_avatar(user_id):
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())

    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    
    valid_user_id = valid_user[0].key.id

    # If JWT is owned by user_id in the path parameter
    if (valid_user_id == user_id):
        # Any files in the request will be available in request.files object
        # Check if there is an entry in request.files with the key 'file'
        if "file" not in request.files:
            raise AuthError(ERROR_400)
        # Set image_obj to the file sent in the request
        image_obj = request.files["file"]
        # Create a storage client
        storage_client = storage.Client()
        # Get a handle on the bucket
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        # Create a blob object for the bucket with the name of the file
        blob = bucket.blob(image_obj.filename)
        # Position the image_obj to its beginning
        image_obj.seek(0)
        # Upload the file into Cloud Storage
        blob.upload_from_file(image_obj)

        # Set the public URL for the image
        avatar_url = request.host_url.rstrip('/') + "/users/" + str(user_id) + "/avatar"
        public_url = blob.public_url

        # Create a profile_image_map entry in Datastore
        # Use avatar_url as the primary key so each mapping is unique
        profile_image_key = datastore_client.key(
            "profile_image_map",
            avatar_url
        )
        profile_image_entity = datastore.Entity(key=profile_image_key)
        profile_image_entity.update({
            "avatar_url": avatar_url,
            "image_url": public_url
        })
        datastore_client.put(profile_image_entity)

        # Fetch user
        key = datastore_client.key("users", user_id)
        user = datastore_client.get(key)

        # Update the user's avatar_url field to the uploaded image's public URL
        user["avatar_url"] = avatar_url
        datastore_client.put(user)

        # 200 OK
        return (
            {
                "avatar_url": avatar_url
            },
            200,
            {"Content-Type": "application/json"}
        )
    # 403 Forbidden
    raise AuthError(ERROR_403)

# Create a new course with the given information in the request body
@app.route('/courses', methods=['POST'])
def create_course():
    # Verify the JWT
    payload = verify_jwt(request)

    # If JWT was absent or invalid, 401 Unauthorized
    if payload == None:
        raise AuthError(ERROR_401)

    # Find the user with the same "sub" as in the payload
    query = datastore_client.query(kind="users")
    query.add_filter("sub", "=", payload["sub"])
    valid_user = list(query.fetch())

    # JWT is invalid if no user with the same "sub", 401 Unauthorized
    if not valid_user:
        raise AuthError(ERROR_401)
    
    # Find the instructor with the id given in the request body
    data = request.get_json()
    instructor_id = data.get("instructor_id")

    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "instructor")
    instructor_users = list(query.fetch())
    instructor_ids = [user.key.id for user in instructor_users]

    # 400 Bad Request
    if instructor_id is None or instructor_id not in instructor_ids:
        raise AuthError(ERROR_400)
    
    # Query for all users with role "admin" and get their "sub" value
    query = datastore_client.query(kind="users")
    query.add_filter("role", "=", "admin")
    admin_users = list(query.fetch())
    admin_subs = [user["sub"] for user in admin_users]

    # If user has admin role
    if (payload["sub"] in admin_subs):
        subject = data.get("subject")
        number = data.get("number")
        title = data.get("title")
        term = data.get("term")

        # 400 Bad Request
        if not subject or not number or not title or not term:
            raise AuthError(ERROR_400)

        # Create the course entity
        course_key = datastore_client.key("courses")
        course_entity = datastore.Entity(key=course_key)
        # Temporarily set self to None, will update after getting id
        course_entity.update({
            "subject": subject,
            "number": number,
            "title": title,
            "term": term,
            "instructor_id": instructor_id,
            "self": None
        })
        datastore_client.put(course_entity)

        # Update the "self" field with the URL to the course
        course_id = course_entity.key.id
        course_self = request.host_url + "courses/" + str(course_id)
        course_entity["self"] = course_self
        datastore_client.put(course_entity)

        # 201 Created
        return (
            jsonify({
                "id": course_id,
                "self": course_self,
                "subject": subject,
                "number": number,
                "title": title,
                "term": term,
                "instructor_id": instructor_id
            }),
            201,
            {"Content-Type": "application/json"}
        )
    # 403 Forbidden
    raise AuthError(ERROR_403)

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

# Frontend route to serve the index.html file
@app.route("/")
def root():
    return render_template("index.html")

# Main function
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)