#从app包中导入 app这个实例
from datetime import datetime

from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from app.email import send_password_reset_email
from app.forms import LoginForm, RegistrationForm, EditProfileForm, ResetPasswordRequestForm, ResetPasswordForm
from app import app, db
from app.modles import User,Post
#2个路由
@app.route('/')
@app.route('/index')
@login_required#装饰器，要求用户登录
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

#查看用户最后访问时间
@app.before_request
def before_request():
	if current_user.is_authenticated:#判断当前用户是否已登录
		current_user.last_seen = datetime.utcnow()
		db.session.commit()

@app.route("/login2",methods=['GET','POST'])
def login():
	if current_user.is_authenticated:
		current_user.last_seen = datetime.utcnow()
		db.session.commit()
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

#用户个人资料页面
@app.route('/user/<username>')
@login_required
def user(username):
	user = User.query.filter_by(username=username).first_or_404()
	posts = [
        {'author':user, 'body':'Test post #1'},
        {'author':user, 'body':'Test post #2'}
    ]
	return render_template('user.html', user=user, posts=posts)

#用户编辑资料
@app.route('/edit_profile',methods=['GET','POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()

        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile', form=form)

@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot follow yourself!')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('You are following {}!'.format(username))
    return redirect(url_for('user', username=username))

@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You are not following {}.'.format(username))
    return redirect(url_for('user', username=username))

@app.route('/reset_password_request', methods=['GET','POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)
