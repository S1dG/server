import os
from dotenv import load_dotenv

from flask import Flask,request,jsonify,make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash,check_password_hash

from sqlalchemy import create_engine, Column, Integer, String, VARCHAR, CHAR, Sequence,select
from sqlalchemy.orm import Session,sessionmaker,declarative_base

load_dotenv()



engine = create_engine("postgresql+psycopg2://adm:pass@localhost:5432/users",echo=True)
Base=declarative_base()

class User(Base):
	__tablename__ = 'User'
	uid=Column('uid',Integer,Sequence('uid',100),primary_key=True)
	email=Column('email',VARCHAR(255))
	password=Column('password',VARCHAR(255))


	def __init__(self,email):
		self.email=email

	def __repr__(self):
		return f'''<uid>:{self.uid} <email>:{self.email} <pwd>:{self.password}'''#'<User %r>' % self

	def set_password(self,password) -> None:
		self.password=generate_password_hash(password)

	def check_password(self,password) -> bool:
		return check_password_hash(self.password,password)


Base.metadata.create_all(engine)  # this line connects to engine and take all the classes that extend from Base class and creates respective table inside the engine

app=Flask(__name__)



app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

jwt=JWTManager(app)

@app.route('/')
def hello_world():
	return 'this works'


@app.route("/signup",methods=["POST"])
def signup():
	auth=request.get_json()
	email=auth['email'].lower()
	password=auth['pwd']

	#  TODO create a password hash and store it in db and return user created
	if not email or not password:
		return jsonify({"message":"Both Email or Password are required"}),400
	with (Session(engine) as session):
		existing_user = session.scalars(select(User).filter_by(email=email).limit(1)).all()
		print('user is:', existing_user)
		if existing_user:
			return jsonify({"message":"Email already in use, LogIn to continue"}),400

		try:
			new_user=User(email=email)
			new_user.set_password(password)
			session.add(new_user)
			session.commit()
			return jsonify({"message":"user successfully created."}), 201
		except Exception as e:
			print(e)
			return jsonify({"message":"some error has occurred"}),400


@app.route("/login",methods=["POST"])
def login_user():
	auth:dict=request.get_json()
	email=auth.get('email',None)
	password=auth.get('pwd',None)
	print('email',email,'password',password)

	# if email or password not found
	if None in (email,password):
		return jsonify({"message":"both email and password are required"}),401
		# returns 401 if any email or / and password is missing
		# return make_response(
		# 	'Could not verify',
		# 	401,
		# 	{'WWW-Authenticate': 'Basic realm ="Login required !!"'}
		# )
	with (Session(engine) as session):
		existing_user = session.scalars(select(User).filter_by(email=email).limit(1)).all()
		if not existing_user:
			return jsonify({"message":"User does not exist"}),401
		user=existing_user[0]
		if not user.check_password(password):
			return jsonify({"message":"wrong password"}),401
		access_token=create_access_token(identity=user.uid)
		return jsonify({"jwt":access_token}),200


if __name__=="__main__":
	app.run(debug=True)