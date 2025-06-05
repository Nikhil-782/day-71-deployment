from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user,login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column, Relationship
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm,CommentForm
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,EmailField,PasswordField
from wtforms.validators import DataRequired

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
def admins_only(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
            if current_user.id!=1:
                return abort(403)
            else:
                return  f(*args,**kwargs)
    return wrapper
# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    email = EmailField("Email",validators=[DataRequired()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")
class LoginForm(FlaskForm):
    email = EmailField("Email",validators=[DataRequired()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Log In")

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    comment_author = relationship("Users",back_populates="comments")#Users
    users_id:Mapped[int] = mapped_column(Integer,db.ForeignKey("Users.id"))#Users
    comment_author2 = relationship("BlogPost",back_populates="comments")#BlogPost
    blogpost_id:Mapped[int] = mapped_column(Integer,db.ForeignKey("blog_posts.id"))#BlogPost
# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    users_id:Mapped[int] = mapped_column(Integer,db.ForeignKey("Users.id"))#Users
    author = relationship("Users",back_populates="posts")#Users
    comments = relationship("Comment",back_populates="comment_author2")#Comment

# TODO: Create a User table for all your registered users.

class Users(db.Model,UserMixin):
    __tablename__ = "Users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(150), nullable=False)
    posts = relationship("BlogPost", back_populates="author")#BlogPost
    comments = relationship("Comment",back_populates="comment_author")#Comment
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)

with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        if Users.query.filter(Users.email == email).first() and Users.query.filter(Users.name == name).first():
            flash("Username & Email already exists!")
            return render_template("register.html", form=form, logged_in=current_user.is_authenticated)

        if Users.query.filter(Users.email == email).first():
            flash("Email already exists!")
            return render_template("register.html", form=form, logged_in=current_user.is_authenticated)

        if Users.query.filter(Users.name == name).first():
            flash("Username already exists!")
            return render_template("register.html", form=form, logged_in=current_user.is_authenticated)

        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = Users(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email.
@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email=form.email.data
        user = Users.query.filter(Users.email==email).first()
        if user:
            password = form.password.data
            if check_password_hash(user.password,password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Recheck The Password")
        else:
            flash("Email not exists")
    return render_template("login.html",form=form,logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods=['GET','POST'])
@login_required
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment=form.comment.data
        new_comment=Comment(text=comment,comment_author=current_user,comment_author2=requested_post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post",post_id=post_id))
    comments=Comment.query.filter(Comment.blogpost_id==post_id).all()
    return render_template("post.html", post=requested_post,form=form,comments=comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admins_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admins_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
