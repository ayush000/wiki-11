#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import re
import hmac
from google.appengine.ext import db
import hashlib
import time
import logging

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(autoescape=True, extensions=['jinja2.ext.autoescape'],
                               loader=jinja2.FileSystemLoader(template_dir))

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

# Helper functions
SECRET = "hunter2"


def make_secure_val(s):
    return hashlib.sha256(s).hexdigest()


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val_2(s):
    return "{}|{}".format(s, hash_str(s))


def check_secure_val_2(h):
    val = h.split('|')[0]
    if make_secure_val_2(val) == h:
        return val


def is_logged_in(user):
    loggedin = False
    user_name = None
    # user = self.request.cookies.get('user_id')
    if user:
        user_name = check_secure_val_2(user)
        if user_name:
            loggedin = True
    return loggedin, user_name
    # else:
    #     self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        t = jinja_env.get_template(template)
        self.write(t.render(kw))


# class MainHandler(Handler):
#     def get(self):
#         self.render('base.html')




class Pages(db.Model):
    url = db.StringProperty(required=True)
    content = db.StringProperty(multiline=True)
    created = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    user_name = db.StringProperty(required=True)
    user_password = db.StringProperty(required=True)
    user_email = db.StringProperty()


class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        user_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""
        has_error = False

        def match_user(user):
            USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
            return USER_RE.match(user)

        def match_password(password):
            PASSWORD_RE = re.compile(r"^.{3,20}$")
            return PASSWORD_RE.match(password)

        def match_email(email):
            EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
            return EMAIL_RE.match(email)

        user_name = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')
        user_list = db.GqlQuery('SELECT * FROM User')
        if not match_user(user_name):
            has_error = True
            user_error = "Enter a valid username"
        else:
            for user in user_list:
                if user_name == user.user_name:
                    has_error = True
                    user_error = "User already exists"

        if not match_password(user_password):
            has_error = True
            password_error = "Enter a valid pasword"
        elif not user_password == user_verify:
            has_error = True
            verify_error = "Passwords don't match"
        if user_email:
            if not match_email(user_email):
                has_error = True
                email_error = "Enter a valid email"
        if has_error:
            self.render("signup.html", user_name=user_name, user_email=user_email, user_error=user_error,
                        password_error=password_error, verify_error=verify_error, email_error=email_error)
        else:
            hashed_password = make_secure_val(user_password)
            u = User(user_name=user_name, user_password=hashed_password, user_email=user_email)
            u.put()
            secure_id = make_secure_val_2(user_name)
            self.response.headers.add_header('Set-Cookie', 'user_id={}; Path=/'.format(secure_id))
            self.redirect('/welcome')


class Login(Handler):
    def get(self):
        self.render('login.html')
        red_uri = self.request.referer
        self.response.headers.add_header('Set-Cookie', 'red_uri={}; Path=/'.format(red_uri))

        # self.write('Login page stub')

    def post(self):
        user_name = self.request.get('username')
        red_uri = self.request.cookies.get('red_uri')
        if not red_uri:
            red_uri = "/"
        user_password = self.request.get('password')
        hashed_password = make_secure_val(user_password)
        user_list = db.GqlQuery('SELECT * FROM User')
        user_list = list(user_list)
        for user in user_list:
            if user.user_name == user_name and user.user_password == hashed_password:
                secure_id = make_secure_val_2(user_name)
                self.response.headers.add_header('Set-Cookie', 'user_id={}; Path=/'.format(secure_id))
                self.redirect(str(red_uri))
                # self.write(len(user_list))
        # self.write(red_uri)
        self.render('login.html', user_name=user_name, login_error="Invalid login details")


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect(self.request.referer)
        # self.write('Logout page stub')


class WikiPage(Handler):
    def get(self, page):
        logging.error('open front page')
        loggedin, user_name = is_logged_in(self.request.cookies.get('user_id'))
        if not loggedin:
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        logging.error('ACCESS DB')
        pages = db.GqlQuery("SELECT * FROM Pages WHERE url='{}' ORDER BY created DESC ".format(page))
        pages = list(pages)

        if pages:
            content = pages[0].content
            content = content.replace('\n', '<br>')
            # self.write(content)
            self.render('page.html', loggedin=loggedin, user_name=user_name, pages=pages, ct=content)
        else:
            self.redirect('/_edit{}'.format(page))
            # self.write(loggedin)
        # if page in pages.url:
        # self.write(page)
            # self.write(pages)



class EditPage(Handler):
    def get(self, page):

        loggedin, user_name = is_logged_in(self.request.cookies.get('user_id'))
        if not loggedin:
            self.redirect('/login')
        else:
            ct = ""
            logging.error('ACCESS DB')
            pages = db.GqlQuery("SELECT * FROM Pages WHERE url='{}' ORDER BY created DESC".format(page))
            pages = list(pages)
            if pages:
                ct = pages[0].content
            self.render('edit.html', loggedin=loggedin, user_name=user_name, ct=ct)
            # self.page=page
            # self.write('Wiki edit page stub')
            # self.write(page)

    def post(self, p2):
        content = self.request.get('cont')
        p = Pages(url=p2, content=content)
        logging.error("INSERT IN DB")
        p.put()
        # self.write(p2)
        time.sleep(0.3)
        self.redirect(p2)

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               # ('/',MainHandler)
                               ],
                              debug=True)
