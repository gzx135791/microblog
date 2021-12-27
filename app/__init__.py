#从flask包中导入Flask类
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy#从包中导入类
from flask_migrate import Migrate

#将Flask类的实例 赋值给名为 app 的变量。这个实例成为app包的成员。
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)#数据库对象
migrate = Migrate(app, db)#迁移引擎对象

#print('等会谁（哪个包或模块）在使用我：',__name__)
#print(app.config['SECRET_KEY'])
from app import routes,modles#从app包中导入模块routes