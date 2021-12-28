#从app包中导入 app这个实例
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

from app.forms import LoginForm, RegistrationForm
from app import app, db
from app.modles import User,Post
#2个路由
@app.route('/')
@app.route('/index')
@login_required#要求用户登录装饰器
#1个视图函数
def index():
	# user = {'username': 'gzx'}
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
	return render_template('index.html', title='Home', posts=posts)

@app.route("/login2",methods=['GET','POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	login_form=LoginForm()
	if login_form.validate_on_submit():
		user = User.query.filter_by(username=login_form.username.data).first()
		if user is None or not user.check_password(login_form.password.data):
			flash('Invalid username or password')
			return redirect(url_for('login'))
		login_user(user,remember=login_form.remember_me.data)
		# 重定向到 next 页面
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':#next_page不存在或者next为非本网页
			next_page = url_for('index')
		return redirect(next_page)
		return redirect(url_for('index'))

	# 	flash('Login requested for user {},remember_me={}'.format(login_form.username.data, login_form.remember_me.data))
	# 	return redirect(url_for('index'))
	return render_template('login.html', title='Sign In', form=login_form)

@app.route('/logout')#登出
def logout():
    logout_user()
    return redirect(url_for('index'))

#注册函数
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:#验证用户是否已注册完成
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
