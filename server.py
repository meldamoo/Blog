
#-----------------------------------IMPORTS-----------------------------------#

from datetime import date
from flask import Flask, abort, flash, redirect, \
                    render_template, request, url_for
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import LoginManager, UserMixin, current_user, \
                        login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from forms import CommentForm, CreatePostForm, LoginForm, RegisterForm
from functools import wraps
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

import os

#-------------------------------------SETUP-----------------------------------#

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['APP_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#----------------------------------CLASS DEFS---------------------------------#

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    ## PARENT RELATIONSHIP
    ## 'AUTHOR' => BLOGPOST.AUTHOR
    posts = relationship("BlogPost", back_populates="author")

    ## PARENT RELATIONSHIP
    ## 'COMMENT_AUTHOR' => COMMENT.COMMENT_AUTHOR
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    ## FOREIGN KEY => 'USERS' REFERS TO USER TABLE NAME
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    ## REF TO USER OBJECT. 'POSTS' => USER.POSTS
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    ## PARENT RELATIONSHIP
    ## 'PARENT_POST' => COMMENT.PARENT_POST
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    ## FOREIGN KEY => 'BLOG_POSTS' REFERS TO BLOGPOST TABLE NAME
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    ## ONE POST TO MANY COMMENTS RELATIONSHIP
    ## 'COMMENTS' => BLOGPOST.COMMENTS
    parent_post = relationship( "BlogPost", back_populates="comments" )

    ## FOREIGN KEY => 'USERS' REFERS TO USER TABLE NAME
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    ## ONE USER TO MANY COMMENTS RELATIONSHIP
    ## 'COMMENTS' => USER.COMMENTS
    comment_author = relationship( "User", back_populates="comments" )

    text = db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()

#------------------------------UTILITY FUNCTIONS------------------------------#

##ADMIN-ONLY DECORATOR
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

#---------------------------------MAIN PAGES----------------------------------#

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html",
                            all_posts=posts,
                            current_user=current_user)


@app.route('/about')
def about():
    return render_template("about.html", current_user=current_user)


@app.route('/contact')
def contact():
    return render_template("contact.html", current_user=current_user)

#--------------------------------LOGIN/LOGOUT---------------------------------#

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        ## USER EMAIL IS ALREADY REGISTERED
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(form.password.data,
                                                method='pbkdf2:sha256',
                                                salt_length=8)
        new_user = User(email=form.email.data,
                        name=form.name.data,
                        password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html",
                            form=form,
                            current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        # USER EMAIL IS NOT REGISTERED #
        if not user:
            flash("Email not registered")
            return redirect(url_for('login'))
        # INCORRECT PASSWORD #
        elif not check_password_hash(user.password, password):
            flash("Incorrect password")
            return redirect(url_for('login'))
        # LOGIN CREDENTIALS ARE VALID #
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html",
                            form=form,
                            current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

#---------------------------------BLOGPOSTS-----------------------------------#

@app.route('/post/<int:post_id>', methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))

        new_comment = Comment(text=form.comment_text.data,
                                comment_author=current_user,
                                parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html",
                            post=requested_post,
                            form=form,
                            current_user=current_user)


@app.route('/new-post')
@admin_only
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
        return redirect(url_for('get_all_posts'))

    return render_template("make-post.html",
                            form=form,
                            current_user=current_user)


@app.route('/edit-post/<int:post_id>')
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))

    return render_template("make-post.html",
                            form=edit_form,
                            is_edit=True,
                            current_user=current_user)


@app.route('/delete/<int:post_id>')
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

#------------------------------------------------------------------------------#

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
