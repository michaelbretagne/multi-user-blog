from google.appengine.ext import db
from models.user import User
import environment

# blog stuff

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
        return environment.render_str("post.html", p=self)

