import os
import re
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

#set  template directory jinja env for templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'du.uyx^Ed~ppQ12d'

def render_str(template,**params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' %(val, hmac.new(secret,val).hexdigest)

def check_secure_val(secure_val):
    val= secure_val.split(|)[0]
    if secure_val == make_secure_val(val)
     return val

class Handler(webapp2.RequestHandler):
    def render(self,template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)

    def set_secure_cookie(self,name,val):
        cookie_val= make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' %(name,cookie_val))



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return  email and EMAIL_RE.match(email)


class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not valid username"
            have_error = True
        if not valid_password(password):
            params['error_password'] = "That's not valid password"
            have_error = True
        elif password != verify:
            params['error_verify'] = "password didn't match"
            have_error = True
        if not valid_email(email):
            params['error_email'] = "That's not valid email"
            have_error = True

        if have_error:
            self.render("signup.html",**params)
        else:
            self.redirect('/welcome?username=' +username)

class Welcome(Handler):
    def get(self):
        username = self.request.get("username")
        if valid_username(username):
            self.render('welcome.html',username = username)
        else:
            self.rediect('/signup',)

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get(username)
        password = self.request.get(password)

        u = user.login(username,password)
        if u:
            self.render('/welcome')
        else:
            error = "invalid"
            self.render("login.html",error = erro)




app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/welcome',Welcome),
    ('/login',Login)
], debug=True)
