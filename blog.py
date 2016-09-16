import os
import re
import random
import hashlib
import hmac
import time
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "eloane"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # renders html using templates
        params["user"] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            "Set-Cookie",
            "%s=%s; Path=/" % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie("user_id", str(user.key().id()))

    def logout(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie("user_id")
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write("<b>" + post.subject + "</b><br>")
    response.out.write(post.content)
    response.out.write(post.ingredients_content)


# user stuff
def make_salt(length=5):
    return "".join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(",")[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group="default"):
    return db.Key.from_path("users", group)


class User(db.Model):

    """
    User Class which holds user informations like
    name, hashed password and email
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter("name =", name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name="default"):
    return db.Key.from_path("blogs", name)


class Post(db.Model):

    """
    Post Class which holds informations for each post
    """
    user = db.ReferenceProperty(User)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    ingredients_content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)
    numofcom = db.IntegerProperty(default=0)
    liked = db.IntegerProperty(default=0)
    disliked = db.IntegerProperty(default=0)
    likes_author = db.ListProperty(str)

    def render(self):
        self._render_ingredients = self.ingredients_content.replace(
            "\n", "<br>")
        self._render_content = self.content.replace("\n", "<br>")
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):

    """
    Renders home page with all posts, sorted by date.
    """

    def get(self):
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        self.render("front.html", posts=posts)


class PostPage(BlogHandler):

    """
    Renders the freshly created post page.
    """

    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):

    """
    Creates new post and redirect to a new post page.
    """

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect("/blog")

        subject = self.request.get("subject")
        content = self.request.get("content")
        ingredients_content = self.request.get("ingredients_content")
        author = self.request.get("author")

        # check for subject, ingredients and content
        if subject and content and ingredients_content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content,
                     ingredients_content=ingredients_content,
                     author=author,
                     user=self.user.key())
            p.put()
            self.redirect("/blog/%s" % str(p.key().id()))
        else:
            error = "subject and content and ingredients, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        ingredients_content=ingredients_content,
                        error=error)


class EditPost(BlogHandler):

    """
    Edit/update the subject, ingredients or/and content of a post.
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            content = post.content
            subject = post.subject
            ingredients_content = post.ingredients_content
            # check if the user is the one who created the post
            if post.user.key().id() == self.user.key().id():
                self.render("editpost.html",
                            content=content,
                            ingredients_content=ingredients_content,
                            subject=subject)
            else:
                msg = "This is not your recipe! You cannot edit this post!"
                self.render("error.html", error=msg)
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)
        if self.user:
            subject = self.request.get("subject")
            content = self.request.get("content")
            ingredients_content = self.request.get("ingredients_content")

            # check for subject, content and ingredients
            if subject and content and ingredients_content:
                post.subject = subject
                post.content = content
                post.ingredients_content = ingredients_content
                post.put()
                self.redirect("/blog/%s" % str(post.key().id()))
            else:
                msg = "Subject, content and ingredients, please!"
                self.render("editpost.html",
                            subject=subject,
                            content=content,
                            ingredients_content=ingredients_content,
                            error=msg)
        else:
            self.redirect("/blog")


class DeletePost(BlogHandler):

    """
    Delete post.
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)

            if post.user.key().id() == self.user.key().id():
                self.render(
                    "delete-confirmation.html", comment=post.subject)
            else:
                msg = "This is not your recipe! You cannot delete this post!"
                self.render("error.html", error=msg)
        else:
            msg = "You need to be logged to delete your post!"
            self.render("login-form.html", error=msg)

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)

            # check if user is the one who created the post
            if post.user.key().id() == self.user.key().id():
                post.delete()
                time.sleep(0.1)
                self.redirect("/blog")
            else:
                msg = "This is not your recipe! You cannot delete this post!"
                self.render("error.html", error=msg)
        else:
            msg = "You need to be logged to delete your post!"
            self.render("login-form.html", error=msg)


class MyRecipe(BlogHandler):

    """
    Render own post created by user
    """

    def get(self, user_id):
        allrecipe = Post.all()
        myrecipe = allrecipe.filter("author =", self.user.name)
        self.render("myrecipe.html", posts=myrecipe)


class Comment(db.Model):

    """
    This is a Comment Class, which holds comments information in the database.
    """
    comment = db.TextProperty(required=True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class CommentPost(BlogHandler):

    """
    Comment Post
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            post_id = post.key().id()

            # fetch and render the last 100 comments
            comments = Comment.all().filter("post = ", str(post_id))
            comment = comments.fetch(100)

            self.render("commentpost.html",
                        post=post, comment=comment, post_id=post_id)
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/blog")

        comment = self.request.get("comment")
        author = self.request.get("author")

        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)
        numofcom = post.numofcom

        # for each comment the number of comment increase by 1 in the db
        if comment:
            post.numofcom += 1
            post.put()
            time.sleep(0.1)
            c = Comment(parent=blog_key(),
                        comment=comment,
                        post=post_id,
                        author=author)
            c.put()
            self.redirect("/blog")
        else:
            msg = "Comment something, please!"
            self.render("error.html", error=msg)


class EditComment(BlogHandler):

    """
    Edit comments
    """

    def get(self, post_id, comment_id):
        if self.user:
            keypost = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(keypost)

            keycom = db.Key.from_path(
                "Comment", int(comment_id), parent=blog_key())
            comment = db.get(keycom)
            user = self.user.name
            edit_comment = comment.comment
            author = comment.author

            # check if the comment was created by the user.
            if author == user:
                self.render(
                    "editcomment.html", edit_comment=edit_comment, post=post)
            else:
                msg = "This is not your comment! You cannot edit this post!"
                self.render("error.html", error=msg)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            keypost = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(keypost)

            keycom = db.Key.from_path(
                "Comment", int(comment_id), parent=blog_key())
            comment = db.get(keycom)
            edit_comment = comment.comment

            edited_comment = self.request.get("edit_comment")

            # check for comment
            if edited_comment:
                comment.comment = edited_comment
                comment.put()
                self.redirect("/blog/commentpost/%s" % str(post_id))
            else:
                msg = "Comment, please!"
                self.render("editcomment.html",
                            edit_comment=edit_comment,
                            post=post,
                            error=msg)
        else:
            self.redirect("/blog")


class DeleteComment(BlogHandler):

    """
    Delete comments
    """

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path(
                "Comment", int(comment_id), parent=blog_key())
            comment = db.get(key)
            user = self.user.name
            author = comment.author

            # if the comment was created by the user it renders a
            # confirmation html page.
            if author == user:
                self.render(
                    "delete-confirmation.html", comment=comment.comment)
            else:
                msg = "This is not your comment! You cannot delete this post"
                self.render("error.html", error=msg)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            key_comment = db.Key.from_path(
                "Comment", int(comment_id), parent=blog_key())
            comment = db.get(key_comment)
            key_post = db.Key.from_path(
                "Post", int(post_id), parent=blog_key())
            post = db.get(key_post)

            # check if the author of the comment and the name of the user
            # matches. Then the number of comment decrease by 1 in the db.
            if comment.author == self.user.name:
                post.numofcom -= 1
                post.put()
                comment.delete()
                time.sleep(0.1)
                self.redirect("/blog")

            else:
                msg = "This is not your comment! You cannot delete this post!"
                self.render("error.html", error=msg)
        else:
            msg = "You need to be logged to delete your post!"
            self.render("login-form.html", error=msg)


class Liked(BlogHandler):

    """
    Allow users to like a post.
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = post.author
            likes_author = self.user.name

            # check if the the user is not the author of the post and if he
            # has not already like or dislike the post
            if (likes_author != post_author and likes_author
                    not in post.likes_author):
                post.liked += 1
                post.likes_author.append(likes_author)
                post.put()
                time.sleep(0.1)
                self.redirect("/blog")

            elif likes_author == post_author:
                error = "You cannot like your own recipe!"
                self.render("error.html", error=error)

            else:
                error = "You already vote for this recipe!"
                self.render("error.html", error=error)

        else:
            self.redirect("/login")


class Disliked(BlogHandler):

    """
    Allow user to dislike a post
    """

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = post.author
            likes_author = self.user.name

            # check if the the user is not the author of the post and if he
            # has not already like or dislike this post
            if (likes_author != post_author and likes_author
                    not in post.likes_author):
                post.disliked += 1
                post.likes_author.append(likes_author)
                post.put()
                time.sleep(0.1)
                self.redirect("/blog")

            elif likes_author == post_author:
                error = "You cannot dislike your own recipe!"
                self.render("error.html", error=error)

            else:
                error = "You already vote for this recipe!"
                self.render("error.html", error=error)

        else:
            self.redirect("/login")


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        """
        Sign up validation
        """
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params["error_username"] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params["error_password"] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params["error_verify"] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params["error_email"] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup-form.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render("signup-form.html", error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect("/blog")


class Login(BlogHandler):

    def get(self):
        self.render("login-form.html")

    def post(self):
        """
        Login validation
        """
        username = self.request.get("username")
        password = self.request.get("password")

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/blog")
        else:
            msg = "Invalid login"
            self.render("login-form.html", error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect("/blog")

app = webapp2.WSGIApplication([("/", BlogFront),
                               ("/blog/?", BlogFront),
                               ("/blog/([0-9]+)", PostPage),
                               ("/blog/newpost", NewPost),
                               ("/blog/editpost/([0-9]+)", EditPost),
                               ("/blog/deletepost/([0-9]+)", DeletePost),
                               ("/blog/permalink/([0-9]+)", PostPage),
                               ("/blog/myrecipe/([0-9]+)", MyRecipe),
                               ("/blog/commentpost/([0-9]+)", CommentPost),
                               ("/blog/([0-9]+)/editcomment/([0-9]+)",
                                EditComment),
                               ("/blog/([0-9]+)/deletecomment/([0-9]+)",
                                DeleteComment),
                               ("/blog/([0-9]+)/liked", Liked),
                               ("/blog/([0-9]+)/disliked", Disliked),
                               ("/signup", Register),
                               ("/login", Login),
                               ("/logout", Logout),
                               ],
                              debug=True)
