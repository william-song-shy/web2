from flask_login import LoginManager, UserMixin,current_user,login_user,logout_user,login_required
import os
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, flash, request, redirect, url_for,abort
from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField, StringField,PasswordField,BooleanField
from wtforms.validators import InputRequired, NumberRange, DataRequired,Length
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
import click
app = Flask(__name__)
app.secret_key = '11451419260817avdgsjrhsjaj4'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+app.root_path+'/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

#print (db)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.cli.command()
@click.option('--username', prompt=True, help='Admin Username')
@click.option('--password', prompt=True, help='Admin Password', confirmation_prompt=True, hide_input=True)
def init_admin(username,password):
    #print (username,password)
    admin=User(username=username,is_admin=True)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    click.echo('done.')

@login_manager.user_loader
def load_user(user_id):
    user=User.query.get(int(user_id))
    return user    

class Place (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    belonger = db.Column(db.String, default='System')
    x = db.Column(db.Integer)
    y = db.Column(db.Integer)

@app.route('/login',methods=['GET','POST'])
def login ():
    class LoginForm(FlaskForm):
        username = StringField('Username', validators=[DataRequired(), Length(1, 20)])
        password = PasswordField('Password', validators=[DataRequired(), Length(1, 128)])
        remember = BooleanField('Remember me')
        submit = SubmitField('Log in')
    if current_user.is_authenticated:
        return redirect('/admin')
    form=LoginForm()
    if form.validate_on_submit():
        username=form.username.data
        password=form.password.data
        remember=form.remember.data
        admin=User.query.filter(User.username==username).first()
        #print (User.query.all())
        if admin:
            if admin.validate_password(password):
                login_user(admin,remember)
                return redirect('/admin')
    return render_template('login.html',form=form,the_title='登录')



@app.cli.command()
def initdb():
    db.create_all()


@app.route("/<int:x>-<int:y>")
def ok(x, y) -> str:
    if x > 2000 or y > 2000:
        return "<strong> Soo big </strong>"
    return render_template("wei.html",
                           the_title="具体位置",
                           the_xz=str(x+1),
                           the_x=str(x),
                           the_xj=str(x-1),
                           the_yz=str(y+1),
                           the_y=str(y),
                           the_yj=str(y-1))


@app.route("/<int:x>-<int:y>", methods=['POST'])
def seew(x, y):
    # p=Place(x=x,y=y,belonger='me')
    # db.session.add(p)
    # db.session.commit()
    # print (Place.query.all().x)
    if Place.query.filter(Place.x == x, Place.y == y).count() == 0:
        p = Place(x=x, y=y,
                  belonger='system')
        db.session.add(p)
        db.session.commit()
    return render_template('seeplace.html', the_title="位置信息", place=Place.query.filter(Place.x == x, Place.y == y).first())


@app.route("/", methods=['GET', 'POST'])
def main():
    class MainForm(FlaskForm):
        x = IntegerField('x', [InputRequired(), NumberRange(1, 2000)])
        y = IntegerField('y', [InputRequired(), NumberRange(1, 2000)])
        submit = SubmitField('跳转!')
    form = MainForm()
    if form.validate_on_submit():
        x = form.x.data
        y = form.y.data
        #print (form.data)
        return redirect('/{}-{}'.format(x, y))
    return render_template('main.html', form=form, the_title='主页')


@app.route("/admin", methods=['GET', 'POSt'])
def admin():
    if not current_user.is_authenticated:
        abort(403)
    class AdminForm(FlaskForm):
        x = IntegerField('x', [InputRequired(), NumberRange(1, 2000)])
        y = IntegerField('y', [InputRequired(), NumberRange(1, 2000)])
        belonger = StringField('belonger', validators=[DataRequired()])
        submit = SubmitField('更改')
    form = AdminForm()
    if form.validate_on_submit():
        p = Place.query.filter(Place.x == form.x.data,
                               Place.y == form.y.data).first()
        if p == None:
            p = Place(x=form.x.data, y=form.y.data,
                      belonger=form.belonger.data)
            db.session.add(p)
            db.session.commit()
        else:
            p.belonger = form.belonger.data
            db.session.add(p)
            db.session.commit()
        return redirect('/admin')
    return render_template('admin.html', form=form, the_title='管理后台')
@app.route("/logout")
@login_required
def logout ():
    logout_user()
    return redirect('/')