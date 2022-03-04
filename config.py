
import os

basedir = os.path.abspath(os.path.dirname(__file__))#获取当前.py文件的绝对路径



basedir = os.path.abspath(os.path.dirname(__file__))  # 获取当前.py文件的绝对路径

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, 'microblog.env'))


class Config:
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'you will never guess'

	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or 'sqlite:///' + os.path.join(basedir, 'app.db')

	SQLALCHEMY_TRACK_MODIFICATIONS = False

	POSTS_PER_PAGE = 3
