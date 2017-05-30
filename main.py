import re
from string import letters
import hmac

import webapp2
from google.appengine.ext import db

import helper

secret = 'happy'

def make_secure_val(val):
    """
        create secure value using secret
    """
    return '%s|%s' %(val, hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
    """
     verify secure value against secret
    """
    val= secure_val.split(|)[0]
    if secure_val == make_secure_val(val)
     return val

class Handler(webapp2.RequestHandler):
    """
     This Handler class, inherites from webapp2.RequestHandler
     and provides helper method
    """
    def render_str(self, template, **params):
        """
            This methods renders html using template.
        """
        params['user'] = self.user
        return helper.jinja_render_str(template, **params)

    def render(self,template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self,*a,**kw):
        """
         This methods write output to client browser.
        """
        self.response.out.write(*a,**kw)


    def set_secure_cookie(self,name,val):
        """
            set secure cookie to browser.
        """
        cookie_val= make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' %(name,cookie_val))


    def read_secure_cookie(self,name,val):
        """
         Read secure cookie to browser
        """
        cookie_val=self.request.cookies.get(name)
        return cookie_val and make_secure_val(cookie_val)

    def login(self,user):
        """
            verifies user existance.
        """
        self.set_secure_cookie('user_id',str(user.key().id()))

    def logout(self):
        """
            remove all imformation from cookies
        """
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')

    def initialize(self,*a,**kw):
        """
            This methods gets executed for each page and
            verfies user login status, using cookie information.
        """
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def blog_key(name='default'):
        return db.Key.from_path('blog',name)

    class BlogFront(Handler):
        def get(self):
        """
            this renders home page with all post ,sort by Date
        """
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        deleted_post_id = self.request.get('deleted_post_id')
        self.render('front.html',posts=posts,deleted_post_id=deleted_post_id)




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
