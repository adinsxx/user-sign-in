import os
import re
import random
import hashlib
import hmac
import logging
from string import letters

import webapp2
import jinja2

SECRET = 'thisisasecretlol'

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#inheritance
class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
#defines username, password, and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)


#hasing and salting user info
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s,%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split(',')[0]
    if h == make_secure_val(val):
        return val

def make_salt():
    return ''.join((random.choice(string.letters) for x in xrange(5)))

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StrongProperty(required = True)
    email = db.StringProperty()

#defines sign up parameters: valid email/username/password/password verify
class Signup(BaseHandler):
    def get(self):
        self.render("sign-up-text.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        #responses should the user not meet the necessary parameters
        if not valid_username(username):
           params['error_username'] = "Invalid username. It'll come to you!"
           have_error = True

        if not valid_password(password):
           params['error_password'] = "Invalid password. Try again!"
           have_error = True
        elif password != verify:
           params['error_verify'] = "Your passwords don't match. You got this!"
           have_error = True
        
        if not valid_email(email):
           params['error_email'] = "Invalid email. I'm sure it was just a typo!"
           have_error = True

        if have_error:
           self.render('sign-up-text.html', **params)
        else:
           self.redirect('/welcome-page?username=' + username)
           
#Welcomes the user once they have completed a successful sign up/sign in
class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
           self.render('/welcome-page.html', username = username)
        else:
           self.redirect('/Signup')



app = webapp2.WSGIApplication([('/unit2/signup', MainPage),
                               ('/unit2/welcome', Welcome)],
                              debug=True)
