#!/usr/bin/env python

# Copyright 2016 PrettyGoodPasswords
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

import uuid
import logging
import csv
import datetime

from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from webapp2_extras import sessions

import jinja2
import webapp2
import smail

from constants import *
import crypto_helper as crypt

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


class Entry(ndb.Model):
    """A model for representing a password entry.
    user_id is the hashed GAE user id.
    all other entries are encrypted.
    """
    user_id = ndb.StringProperty()
    site = ndb.StringProperty()
    username = ndb.StringProperty()
    password = ndb.StringProperty()
    notes = ndb.StringProperty()


class Account(ndb.Model):
    """
    A model for representing a user account access control.
    When too many failed attempts, the account is locked
    and we set a account_lock_hash via email to re-enable the account.
    """
    user_id = ndb.StringProperty()
    master_hash = ndb.TextProperty(indexed=False)
    master_hash_salt = ndb.StringProperty()
    master_hash_cost = ndb.IntegerProperty()
    master_hash_method = ndb.StringProperty()
    key_hash_salt = ndb.StringProperty()
    key_hash_cost = ndb.IntegerProperty()
    key_hash_method = ndb.StringProperty()
    number_failed_attempts = ndb.IntegerProperty()
    account_lock_hash = ndb.StringProperty()


class Login(ndb.Model):
    """
    A model to record logins. Keeps it separate from
    any sensitive information in the Account.
    """
    user = ndb.UserProperty()
    last_login = ndb.StringProperty()
    num_logins = ndb.IntegerProperty()


def entry_key(id):
    """Constructs a Datastore key for a Entry entity.
    """
    return ndb.Key('Entry', long(id))


def user_id_hash(user):
    """
    :param user: GAE user
    :return: a sha512 hash of the user id that helps hide which user
    """
    return crypt.get_password_hash(str(user.user_id()))


def record_login(user, acc):
    """
    :param user: GAE user
    :param acc: Account ndb entry
    Modifies the Login entry for this user. Keeps
    Date and time of last login.
    Keeps this separate from any sensitive information.
    """
    la = Login.gql("WHERE user = :1", user)
    if la.count() == 1:
        l = la.get()
    else:
        l = Login()
        l.user = user
        l.num_logins = 0
    l.last_login = str(datetime.datetime.now())
    if l.num_logins:
        l.num_logins += 1
    else:
        l.num_logins = 1
    l.put()


def generate_pbkdf2_hash(acc, passwd):
    """
    :param acc: account entry
    :param passwd: text password
    :return: nothing, modifies account entry to hold hash values
    """
    acc.master_hash_method = HASH_METHOD_PBKDF2
    acc.master_hash_cost, acc.master_hash_salt, acc.master_hash = crypt.make_pbkdf2_hash(passwd)


def check_master_pass(user, passwd, autoUpgrade=True):
    """
    :param user: GAE user
    :param passwd: string password
    :return: True on success, False on failure

    Query the NDB store for the GAE user,
    First check that the user's account is not locked
    via an account_lock_hash. If not, then hash the
    passwd passed in and verify against stored hash.
    Clear any previous failed attempts on success.
    """
    acc_q = Account.gql("WHERE user_id = :1", user_id_hash(user))
    if acc_q.count() != 1:
        return False
    ret_val = False
    acc = acc_q.get()

    if acc.account_lock_hash is None:
        stored_h = acc.master_hash
        # handle different hash methods
        if acc.master_hash_method is None:
            acc.master_hash_method = HASH_METHOD_SHA512

        if acc.master_hash_method == HASH_METHOD_SHA512:
            check_h = crypt.get_password_hash(passwd)
            ret_val = (stored_h == check_h)
        elif acc.master_hash_method == HASH_METHOD_PBKDF2:
            ret_val = crypt.check_pbkdf2_hash(passwd, acc.master_hash_cost, acc.master_hash_salt, acc.master_hash)

        if ret_val is True and acc.master_hash_method == HASH_METHOD_SHA512 and autoUpgrade:
            # upgrade hash to HASH_METHOD_PBKDF2
            generate_pbkdf2_hash(acc, passwd)
            acc.put()

        # if we have any failed attempts, clear them when we get a valid attempt.
        if ret_val is True and acc.number_failed_attempts is not None:
            acc.number_failed_attempts = None
            acc.put()

        if ret_val:
            record_login(user, acc)

    return ret_val


def attempt_unlock(user, auth):
    """
    :param user: GAE user
    :param auth: string code
    :return: -1 on failure, or else number of previous failed attempts

    Query the NDB store for the GAE user,
    Check that the account has stored a valid account_lock_hash
    and that it matches the value passed in as auth.
    Will reset the hash and failed attempt account on success.
    """
    acc_q = Account.gql("WHERE user_id = :1", user_id_hash(user))
    if acc_q.count() != 1:
        return -1
    num_attempts = 0
    acc = acc_q.get()
    if acc.account_lock_hash is not None and acc.account_lock_hash == auth:
        acc.account_lock_hash = None
        num_attempts = acc.number_failed_attempts
        acc.number_failed_attempts = 0
        acc.put()
        return num_attempts
    return -1


def has_set_master_pass(user):
    """
    :param user: GAE user
    :return: True when user has set a master password, else False

    Check the master_hash field of Account for that user and make sure it's been set.
    """
    acc_q = Account.gql("WHERE user_id = :1", user_id_hash(user))
    print acc_q.count()
    if acc_q.count() != 1:
        return False
    return acc_q.get().master_hash != None


def init_key(passwd, acc=None):
    """
    :param passwd: a string
    :return: a string that is suitable for use as a key in ciphers
    """
    acc.key_hash_method = HASH_METHOD_PBKDF2
    acc.key_hash_cost, acc.key_hash_salt, hash = crypt.make_pbkdf2_hash(passwd)
    return hash


def make_key(passwd, acc=None):
    """
    :param passwd: a string
    :return: a string that is suitable for use as a key in ciphers
    """
    if acc is None or acc.key_hash_method is None:
        return crypt.generate_key_from_pass(passwd)
    elif acc.key_hash_method == HASH_METHOD_PBKDF2:
        cost, salt, hash = crypt.make_pbkdf2_hash(passwd, cost=acc.key_hash_cost, salt=acc.key_hash_salt)
        return hash
    return crypt.generate_key_from_pass(passwd)


class BaseHandler(webapp2.RequestHandler):
    """
    A base class for all request handlers in order to collect
    shared code.
    """

    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

    def init_user(self):
        """
        sets the self.user to the current user
        :return: returns True when set
        """
        self.user = users.get_current_user()
        return self.user != None

    def render(self, template_values, html_file):
        """
        :param template_values: dict of values to be passed to template engine
        :param html_file: source html file
        :return: nothing

        writes a final html page for display, given the template and rendering engine.
        """
        template = JINJA_ENVIRONMENT.get_template(html_file)
        self.response.write(template.render(template_values))

    def is_not_authorized(self):
        """
        :return: True when not authorized.
        Convenience function to check session value to see if master pass has been provided correctly.
        """
        authorized = self.session.get('authorized')
        return not authorized

    def is_authorized(self):
        """
        :return: True when authorized
        Convenience function to check session value to see if master pass has been provided correctly.
        """
        authorized = self.session.get('authorized')
        return authorized

    def set_authorized(self, val, key=None):
        """
        :param val: a bool value to indicate whether we have passed master password check
        :param key: a string key value to be cached in the session for later use in ciphers
        :return: nothing
        """
        self.session['authorized'] = val
        self.session['key'] = key

    def get_key(self):
        """
        :return: a string value of the private key stored for this user. May be None.
        """
        return self.session.get('key')

    def is_mobile(self):
        """
        :return: True when running on a mobile device such as phone or tablet.
        """
        if DEVELOPER_MODE:
            return FAKE_MOBILE
        uastring = self.request.headers.get('user_agent')
        return "Mobile" in uastring

    def template(self, html):
        """
        :param html: html filename without template path
        :return: the final html filename with a template path
        checks the platform and uses appropriate template path.
        """
        if self.is_mobile():
            if USE_JQ_MOBILE:
                return "jq_templates/%s" % html
            else:
                return "ang_templates/%s" % html
        return "templates/%s" % html

    def decode_entry(self, entry, aes_key=None, cipher=None):
        """
        :param entry: NDB Entry class
        :param aes_key: optional string key
        :param cipher: optional cipher
        :return: None
        Decrypts each field of the Entry passed in with the given cipher.
        If none given, we check the session to construct the cipher.
        """
        if not cipher:
            if not aes_key:
                aes_key = self.get_key()
            cipher = crypt.create_cipher(aes_key)
        entry.site = crypt.decode(entry.site, cipher)
        entry.username = crypt.decode(entry.username, cipher)
        entry.password = crypt.decode(entry.password, cipher)

        if entry.notes:
            entry.notes = crypt.decode(entry.notes, cipher)
        else:
            entry.notes = ''

    def encode_entry(self, entry, aes_key=None, cipher=None):
        """
        :param entry: NDB Entry class
        :param aes_key: optional string key
        :param cipher: optional cipher
        :return: None
        Encrypts each field of the Entry passed in with the given cipher.
        If none given, we check the session to construct the cipher.
        """
        if not aes_key:
            aes_key = self.get_key()
        if not cipher:
            cipher = crypt.create_cipher(aes_key)
        entry.site = crypt.encode(entry.site, cipher)
        entry.username = crypt.encode(entry.username, cipher)
        entry.password = crypt.encode(entry.password, cipher)
        if entry.notes:
            entry.notes = crypt.encode(entry.notes, cipher)
        else:
            entry.notes = ''

    def condition_input(self, value):
        """
        :param value: the string to be conditioned
        :return: a striped string. can't converted to unicode?
        """
        return value.strip()

    def view_welcome(self):
        login_url = users.create_login_url("/")
        self.render({"login_url": login_url}, self.template('welcome.html'))

    def view_entry(self, key_id):
        entry = entry_key(key_id).get()
        if entry is None:
            entry = Entry()
        else:
            self.decode_entry(entry)

        template_values = {
            "entry": entry
        }

        self.render(template_values, self.template('view_entry.html'))

    def view_list(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        user = self.user

        try:
            entries = Entry.gql("WHERE user_id = :1", user_id_hash(user))
        except:
            entries = []

        aes_key = self.get_key()
        if aes_key is None or len(aes_key) < 5:
            self.response.write("Not authorized.")
            return

        cipher = crypt.create_cipher(aes_key)

        # just decode the sites for now. That's all we can see in the list
        entry_list = []
        for e in entries:
            e.site = crypt.decode(e.site, cipher)
            entry_list.append(e)

        entry_list.sort(key=lambda x: x.site.upper(), reverse=False)

        create_action = "ajax_load('/create');"
        create_label = "Create New"

        template_values = {
            "entries": entry_list,
            "header": "Sites",
            "create_label": create_label,
            "create_action": create_action,
        }

        self.render(template_values, self.template('list.html'))


class MainPage(BaseHandler):
    def get(self):
        self.render({}, self.template('main.html'))

class MasterPassForm(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if not has_set_master_pass(self.user):
            self.redirect("/master_init_form")
            return

        if self.is_authorized():
            self.view_list()
            return

        self.render({}, self.template('enter_master_pass.html'))


class CheckMasterPass(BaseHandler):
    def post(self):
        if not self.init_user():
            self.response.write("/welcome")
            return

        if not has_set_master_pass(self.user):
            self.response.write("/master_init_form")
            return

        auth = self.request.get('auth')
        if check_master_pass(self.user, auth, autoUpgrade=True):
            acc_q = Account.gql("WHERE user_id = :1", user_id_hash(self.user))
            key = make_key(auth, acc_q.get())
            self.set_authorized(True, key)
            self.response.write('/list')
        else:
            acc_q = Account.gql("WHERE user_id = :1", user_id_hash(self.user))
            account_locked = False
            for acc in acc_q:
                if acc.number_failed_attempts is None:
                    acc.number_failed_attempts = 0
                acc.number_failed_attempts += 1
                if acc.number_failed_attempts > MAX_ATTEMPTS_PASSWORD:
                    account_locked = True
                    if acc.account_lock_hash is None:
                        logging.error('sending a lock email to: %s' % self.user.email())
                        acc.account_lock_hash = str(uuid.uuid1())
                        sender = APP_EMAIL_NO_REPLY
                        to = self.user.email()
                        subject = "Your account has been locked."

                        body = '''We have received a number of incorrect password attemps to logon to your account.
                        In order to re-enable your account, click on the link below.
                        %s/unlock?auth=%s
                        If you can not click, then copy and paste the url into a browser.
                        Please contact %s if you feel someone is attempting to force access your account.
                        ''' % (SITE_ROOT, acc.account_lock_hash, APP_EMAIL_HELP)

                        html = '''
                        We have received a number of incorrect password attemps to logon to your account.<br>
                        In order to re-enable your account, click on the link below.<br>
                        <a href="%s/unlock?auth=%s">Unlock</a><br>
                        If you can not click, then copy and paste the url into a browser.<br>
                        Please contact <a href="mailto:%s"/>PGP Help</a> if you feel someone is attempting to force access your account.<br>
                        ''' % (SITE_ROOT, acc.account_lock_hash, APP_EMAIL_HELP)

                        # send mail using sendgrid
                        smail.send(sender, to, subject, body, html)
                acc.put()
            if account_locked:
                self.response.write('/locked')
            else:
                self.response.write('/master')


class MasterPassInitForm(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if has_set_master_pass(self.user):
            self.response.write("The master password is already set.")
            return

        self.render({"err": self.request.get("err"), "MIN_MASTER_PASS_STRENGTH": MIN_MASTER_PASS_STRENGTH},
                    self.template('create_master.html'))


class MasterPassChangeForm(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        self.render({"err": self.request.get("err"), "MIN_MASTER_PASS_STRENGTH": MIN_MASTER_PASS_STRENGTH},
                    self.template('change_master.html'))


class InitMasterPass(BaseHandler):
    def post(self):
        if not self.init_user():
            self.response.write("/welcome")
            return
        if self.request.get('agree') != 'on' and not DEVELOPER_MODE:
            self.response.write("/master_init_form?err=You must agree to terms of service.")
            return
        user = users.get_current_user()
        # remove any previous entry.
        acc_q = Account.gql("WHERE user_id = :1", user_id_hash(user))
        for acc in acc_q:
            acc.key.delete()
        acc = Account()
        acc.user_id = user_id_hash(user)
        passwd = self.request.get('password')
        if passwd != self.request.get('password_repeat'):
            self.response.write("/master_init_form?err=Passwords did not matcrypt.")
            return
        strength, improvements = crypt.check_password_strength(passwd)
        iStrength = int(strength * 100.0)

        if iStrength < MIN_MASTER_PASS_STRENGTH and not DEVELOPER_MODE:
            self.response.write("/master_init_form?err=Password strength must be %d or higher. Yours scored %d." % (
            MIN_MASTER_PASS_STRENGTH, iStrength))
        else:
            generate_pbkdf2_hash(acc, passwd)
            record_login(user, acc)
            key = init_key(passwd, acc)
            acc.put()
            self.set_authorized(True, key)
            self.response.write('/list')


class ChangeMasterPass(BaseHandler):
    def post(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        user = users.get_current_user()
        acc_q = Account.gql("WHERE user_id = :1", user_id_hash(user))
        if acc_q.count() != 1:
            self.response.write("/change_master_form?err=Problems accessing old password.")
            return

        acc = acc_q.get()
        if acc.account_lock_hash != None:
            self.response.write("/change_master_form?err=Account is locked.")
            return

        old_passwd = self.request.get('old_password')

        if not check_master_pass(user, old_passwd, autoUpgrade=False):
            self.response.write("/change_master_form?err=Operation failed.")
            return

        passwd = self.request.get('password')
        if passwd != self.request.get('password_repeat'):
            self.response.write("/change_master_form?err=Passwords did not match.")
            return

        strength, improvements = crypt.check_password_strength(passwd)
        iStrength = int(strength * 100.0)

        if iStrength < MIN_MASTER_PASS_STRENGTH and not DEVELOPER_MODE:
            self.response.write("/change_master_form?err=Password strength must be %d or higher. Yours scored %d." % (
                MIN_MASTER_PASS_STRENGTH, iStrength))
        else:
            # decrypt all entries and store them again with new key.
            old_key = self.get_key()
            old_cipher = crypt.create_cipher(old_key)
            new_key = init_key(passwd, acc)
            new_cipher = crypt.create_cipher(new_key)

            entries = Entry.gql("WHERE user_id = :1", user_id_hash(user))

            for e in entries:
                self.decode_entry(e, old_key, old_cipher)
                self.encode_entry(e, new_key, new_cipher)
                e.put()

            # save new master hash
            generate_pbkdf2_hash(acc, passwd)
            acc.put()

            # force them to login again
            self.set_authorized(False, None)

            # should result in redirect
            self.response.write('/master')


class End(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        self.set_authorized(False, None)
        base_url = "/"
        self.render({'google_logout': users.create_logout_url(base_url)}, self.template('logged_out.html'))


class ViewList(BaseHandler):
    def get(self):
        self.view_list()


class SearchForm(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return
        self.render({}, self.template('search_form.html'))


class SearchList(BaseHandler):
    def post(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        user = self.user

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        try:
            entries = Entry.gql("WHERE user_id = :1", user_id_hash(user))
        except:
            entries = []

        matched_entries = []

        query = self.request.get('query').upper()
        aes_key = self.get_key()
        cipher = crypt.create_cipher(aes_key)

        for entry in entries:
            entry.site = crypt.decode(entry.site, cipher)
            if entry.site.upper().find(query) != -1:
                matched_entries.append(entry)

        matched_entries.sort(key=lambda x: x.site.upper(), reverse=False)

        create_action = "ajax_load('/create');"
        create_label = "Create New"

        template_values = {
            "entries": matched_entries,
            "header": "Search Results"
        }

        self.render(template_values, self.template('list.html'))


class ViewEntry(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        user = self.user
        key_id = self.request.get('key')
        self.view_entry(key_id)


class FormEditor(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        key_id = self.request.get('key')
        entry = entry_key(key_id).get()
        if entry is None:
            entry = Entry()
        else:
            self.decode_entry(entry)

        template_values = {
            "entry": entry
        }

        self.render(template_values, self.template('edit.html'))


class Create(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        self.render({}, self.template('create.html'))


class Update(BaseHandler):
    def post(self):
        user = users.get_current_user()
        if not user:
            return
        if self.is_not_authorized():
            self.response.write("Not Authorized.")
            return

        entry = None
        key_id = self.request.get('key')

        if key_id is not None and key_id.isdigit():
            entry = entry_key(key_id).get()
        if entry is None:
            entry = Entry()

        entry.user_id = user_id_hash(user)
        entry.site = self.condition_input(self.request.get('site'))
        entry.username = self.condition_input(self.request.get('username'))
        entry.password = self.condition_input(self.request.get('password'))
        entry.notes = self.condition_input(self.request.get('notes'))

        self.encode_entry(entry)
        entry.put()
        self.view_entry(entry.key.id())


class Delete(BaseHandler):
    def get(self):
        if self.is_not_authorized():
            return
        user = users.get_current_user()
        key_id = self.request.get('key')
        if key_id is not None and key_id.isdigit():
            entry = entry_key(key_id).get()
            if entry is not None:
                entry.key.delete()
        self.view_list()


class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def clean_up(self):
        upload_files = self.get_uploads('files[]')
        for info in upload_files:
            blobstore.delete(info.key())

    def post(self):
        upload_files = self.get_uploads('files[]')
        ret = []
        file_info = None
        for info in upload_files:
            file_info = info
            ret.append(str(info))
            ret.append("<br>")
        user = users.get_current_user()

        if file_info is None:
            self.response.write("something wrong with file upload.")
            self.clean_up()
            return

        if user is None:
            self.response.write('must be logged in to sumbit file for import.')
            self.clean_up()
            return

        self.session_store = sessions.get_store(request=self.request)
        session = self.session_store.get_session()
        aes_key = session.get('key')
        if aes_key is None or len(aes_key) < 5:
            self.response.write('Key not available.')
            self.clean_up()
            return

        cipher = crypt.create_cipher(aes_key)

        reader = blobstore.BlobReader(file_info)
        csv_reader = csv.reader(reader, dialect=csv.excel)
        have_headers = False
        num_imported = 0
        num_skipped = 0
        line_num = 1
        err = []
        entries = []

        try:
            for tokens in csv_reader:
                line_num = line_num + 1
                if not have_headers:
                    n = len(tokens)
                    iSite = self.which_index(tokens, "site")
                    iUser = self.which_index(tokens, "username")
                    iPass = self.which_index(tokens, "password")
                    iNotes = self.which_index(tokens, "notes")
                    if iSite is None or iUser is None or iPass is None:
                        summary = 'The first line of the comma seperated file must contain at least three fields with the exact name: site, username, password. notes are optional.'
                        self.render({"summary": summary}, self.template('import_summary.html'))
                        self.clean_up()
                        return
                    have_headers = True
                else:
                    if len(tokens) != n:
                        err.append('skipped line %d because it had %d tokens, not %d as expected.' % (
                            line_num, len(tokens), n))
                        err.append(','.join(tokens))
                        err.append(" ")
                        num_skipped = num_skipped + 1
                    else:
                        e = Entry()
                        e.user_id = user_id_hash(user)
                        _site = self.condition_input(tokens[iSite])
                        _username = self.condition_input(tokens[iUser])
                        _password = self.condition_input(tokens[iPass])
                        if iNotes is not None:
                            _notes = self.condition_input(tokens[iNotes])
                            _notes = _notes.replace('\\n', '\n')
                            _notes = _notes.replace('\\', '')
                        else:
                            _notes = ""
                        prev_pass = _password
                        try:
                            e.site = crypt.encode(_site, cipher)
                            e.username = crypt.encode(_username, cipher)
                            e.password = crypt.encode(_password, cipher)
                            e.notes = crypt.encode(_notes, cipher)
                            if prev_pass == crypt.decode(e.password, cipher):
                                e.put()
                                num_imported = num_imported + 1
                                entries.append(e)
                            else:
                                num_skipped = num_skipped + 1
                                err.append('problems with line %d site: %s the pasword "%s", had to skip it.' % (
                                    line_num, _site, prev_pass))
                                err.append(" ")
                        except:
                            num_skipped = num_skipped + 1
                            err.append('problems with line %d site: %s the pasword "%s", had to skip it.' % (
                                line_num, _site, prev_pass))
                            err.append(" ")
        except csv.Error as e:
            err = ['Exception at line: %d: %s. Had to stop reading file.' % (csv_reader.line_num, e)]

        for e in entries:
            self.decode_entry(e, cipher)

        summary = ('%d records imported. %d skipped.' % (num_imported, num_skipped))
        self.render({"summary": summary,
                     "entries": entries,
                     "problems": err}, self.template('import_summary.html'))

        self.clean_up()

    def condition_input(self, value):
        """
        :param value: the string to be conditioned
        :return: a string quotes removed and converted to unicode
        """
        return unicode(value.strip('"'), 'utf-8')

    def decode_entry(self, entry, cipher):
        entry.site = crypt.decode(entry.site, cipher)
        entry.username = crypt.decode(entry.username, cipher)
        entry.password = crypt.decode(entry.password, cipher)

        if entry.notes:
            entry.notes = crypt.decode(entry.notes, cipher)
        else:
            entry.notes = ''

    def render(self, template_values, html_file):
        template = JINJA_ENVIRONMENT.get_template(html_file)
        self.response.write(template.render(template_values))

    def is_not_authorized(self):
        authorized = self.session.get('authorized')
        return not authorized

    def is_authorized(self):
        authorized = self.session.get('authorized')
        return authorized

    def set_authorized(self, val, k=None):
        self.session['authorized'] = val
        self.session['key'] = k

    def get_key(self):
        return self.session.get('key')

    def is_mobile(self):
        uastring = self.request.headers.get('user_agent')
        return "Mobile" in uastring

    def template(self, html):
        if self.is_mobile() and USE_JQ_MOBILE:
            return "jq_templates/%s" % html
        return "templates/%s" % html

    def which_index(self, headers, label):
        for i in range(0, len(headers)):
            if headers[i].find(label) != -1:
                return i
        return None


class Tools(BaseHandler):
    def get(self):
        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return
        admin = 0
        user = users.get_current_user()
        if (user and user.email() == ADMIN_EMAIL) or DEVELOPER_MODE:
            admin = 1
        self.render({"admin": admin, "APP_EMAIL_HELP": APP_EMAIL_HELP}, self.template('tools.html'))


class CleanConfirm(BaseHandler):
    def get(self):
        if self.is_not_authorized():
            return

        self.render({}, self.template('clean_confirm.html'))


class Clean(BaseHandler):
    def get(self):
        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return
        user = users.get_current_user()
        entries = Entry.gql("WHERE user_id = :1", user_id_hash(user))
        for e in entries:
            e.key.delete()
        entries = Account.gql("WHERE user_id = :1", user_id_hash(user))
        for e in entries:
            e.key.delete()
        for b in blobstore.BlobInfo.all():
            blobstore.delete(b.key())
        self.set_authorized(False, None)
        self.response.write("all erased.")


class CleanAll(BaseHandler):
    def get(self):
        if not DEVELOPER_MODE:
            self.response.write("Not authorized.")
            return
        entries = Entry.query()
        for e in entries:
            e.key.delete()
        entries = Account.query()
        for e in entries:
            e.key.delete()
        for b in blobstore.BlobInfo.all():
            blobstore.delete(b.key())
        self.response.write("all erased.")


class Import(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        self.render({'form_action': blobstore.create_upload_url('/upload')}, self.template('import.html'))


class Export(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        aes_key = self.get_key()
        if aes_key is None or len(aes_key) < 5:
            self.response.write("Not authorized.")
            return

        cipher = crypt.create_cipher(aes_key)
        entries = Entry.gql("WHERE user_id = :1", user_id_hash(self.user))

        # just decode the sites for now. That's all we can see in the list
        entry_list = []
        for e in entries:
            self.decode_entry(e, aes_key, cipher)
            entry_list.append(e)

        self.response.headers['Content-Type'] = 'application/csv'
        self.response.headers['Content-Disposition'] = 'attachment; filename=passwords.csv'
        writer = csv.writer(self.response.out)
        writer.writerow(["site", "username", "password", 'notes'])
        for entry in entry_list:
            writer.writerow([entry.site.strip(), entry.username.strip(), entry.password.strip(), entry.notes.strip()])


class About(BaseHandler):
    def get(self):
        self.render({"APP_EMAIL_HELP": APP_EMAIL_HELP}, self.template('about.html'))


class Terms(BaseHandler):
    def get(self):
        self.render({}, self.template('terms.html'))


class Locked(BaseHandler):
    def get(self):
        self.render({}, self.template('locked.html'))


class Start(BaseHandler):
    def get(self):
        self.redirect("/")


class Welcome(BaseHandler):
    def get(self):
        base_url = "/"
        login_url = users.create_login_url(base_url)
        self.render({"login_url": login_url}, self.template('welcome.html'))


class Donate(BaseHandler):
    def get(self):
        self.render({"APP_EMAIL_HELP": APP_EMAIL_HELP}, self.template('donate.html'))


class OnDonated(BaseHandler):
    def post(self):
        body = "A donation was made. \n"
        body += "url: %s \n" % self.request.url
        body += "email: %s \n" % self.request.get("receiver_email")
        smail.send(APP_EMAIL_NO_REPLY, ADMIN_EMAIL, "donation", body, body)
        self.response.write("OK.")


class Thanks(BaseHandler):
    def get(self):
        self.render({"APP_EMAIL_HELP": APP_EMAIL_HELP}, self.template('thanks.html'))


class PasswordStrength(BaseHandler):
    def post(self):
        passwd = self.request.get('password')
        strength, improvements = crypt.check_password_strength(passwd)
        iStrength = int(strength * 100.0)

        if strength < 0.1:
            desc = "Terrible"
            style = "terrible"
        elif strength < 0.3:
            desc = "Weak"
            style = "weak"
        elif strength < 0.5:
            desc = "Moderate"
            style = "ok"
        else:
            desc = "Strong"
            style = "strong"

        templates_vals = {"strength": strength,
                          "iStrength": iStrength,
                          "improvements": improvements,
                          "desc": desc,
                          "style": style}

        self.render(templates_vals, self.template('password_meter.html'))


class Unlock(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        auth = self.request.get('auth')
        num_failed_attempts = attempt_unlock(self.user, auth)

        if num_failed_attempts >= 0:
            self.render({'num_failed_attempts': num_failed_attempts}, self.template('unlocked.html'))
        else:
            logging.error('user: %s failed to unlock their account.' % (str(self.user)))
            self.redirect("/")


class Raw(BaseHandler):
    def get(self):
        if not self.init_user():
            self.redirect("/welcome")
            return

        if self.is_not_authorized():
            self.response.write("Not authorized.")
            return

        try:
            entries = Entry.gql("WHERE user_id = :1", user_id_hash(self.user))
        except:
            entries = []

        try:
            accounts_arr = Account.gql("WHERE user_id = :1", user_id_hash(self.user))
            account = accounts_arr.get()
        except:
            account = None

        try:
            login_q = Login.gql("WHERE user = :1", self.user)
            login = login_q.get()
        except:
            login = None

        template_values = {
            "entries": entries,
            "account": account,
            "login": login,
        }

        self.render(template_values, self.template('raw.html'))


class Admin(BaseHandler):
    def get(self):
        logins = Login.query()
        self.render({"logins": logins}, self.template('admin.html'))


class Migrate(BaseHandler):
    def get(self):
        """
        Do some data migration here.
            """
        self.response.write('done.')


class LoginStateCheck(BaseHandler):
    def get(self):
        if not self.init_user() or self.is_not_authorized():
            self.response.write("0")
            return
        self.response.write("1")


config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': SERVER_SESSION_KEY,
}

# Try to turn down the level of logging.
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("request_log").setLevel(logging.WARNING)
logging.getLogger("module").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# [START app]
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/master', MasterPassForm),
    ('/check_master', CheckMasterPass),
    ('/master_init_form', MasterPassInitForm),
    ('/change_master_form', MasterPassChangeForm),
    ('/init_master', InitMasterPass),
    ('/change_master', ChangeMasterPass),
    ('/list', ViewList),
    ('/search', SearchList),
    ('/search_form', SearchForm),
    ('/view', ViewEntry),
    ('/update', Update),
    ('/edit', FormEditor),
    ('/create', Create),
    ('/end', End),
    ('/clean_confirm', CleanConfirm),
    ('/clean', Clean),
    ('/clean_all', CleanAll),
    ('/delete', Delete),
    ('/tools', Tools),
    ('/import', Import),
    ('/upload', UploadHandler),
    ('/export', Export),
    ('/about', About),
    ('/is_logged_in', LoginStateCheck),
    ('/locked', Locked),
    ('/unlock', Unlock),
    ('/raw', Raw),
    ('/terms', Terms),
    ('/welcome', Welcome),
    ('/start', Start),
    ('/password_strength', PasswordStrength),
    ('/donate', Donate),
    ('/donated', OnDonated),
    ('/thanks', Thanks),
    ('/admin', Admin),
    ('/migrate', Migrate),
], debug=DEVELOPER_MODE, config=config)
# [END app]
