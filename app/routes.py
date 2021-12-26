#从app包中导入 app这个实例
from flask import render_template

from app import app

#2个路由
@app.route('/')

#1个视图函数
def index():
	user = {'username': 'gzx'}
	posts = [  # 创建一个列表：帖子。里面元素是两个字典，每个字典里元素还是字典，分别作者、帖子内容。
		{
			'author': {'username': 'John'},
			'body': 'Beautiful day in Portland!'
		},
		{
		'author': {'username': 'Susan'},
		'body': 'The Avengers movie was so cool!'
		}
	]
	return render_template('index.html', title='Home', user=user, posts=posts)
