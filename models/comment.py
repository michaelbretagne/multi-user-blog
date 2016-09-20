from google.appengine.ext import db


class Comment(db.Model):

    """
    This is a Comment Class, which holds comments information in the database.
    """
    comment = db.TextProperty(required=True)
    post = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
