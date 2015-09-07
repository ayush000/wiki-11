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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(autoescape=True, extensions=['jinja2.ext.autoescape'],
                               loader=jinja2.FileSystemLoader(template_dir))


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        t = jinja_env.get_template(template)
        self.write(t.render(kw))


# class MainHandler(Handler):
#     def get(self):
#         self.render('base.html')




PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'


class Signup(Handler):
    def get(self):
        self.write('Signup page stub')


class Login(Handler):
    def get(self):
        self.render('base.html')
        self.write('Login page stub')


class Logout(Handler):
    def get(self):
        self.write('Logout page stub')


class WikiPage(Handler):
    def get(self, page):
        self.write('Wiki page stub')
        self.write(page)


class EditPage(Handler):
    def get(self, page):
        self.write('Wiki edit page stub')
        self.write(page)


app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               # ('/',MainHandler)
                               ],
                              debug=True)
