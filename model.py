import os
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, VARCHAR, CHAR, Sequence
from sqlalchemy.orm import sessionmaker,declarative_base


engine = create_engine("postgresql+psycopg2://adm:pass@localhost/",echo=True)
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


Session=sessionmaker(engine)



Base.metadata.create_all(engine)  # this line connects to engine and take all the classes that extend from Base class and creates respective table inside the engine

with Session() as session:
	pass