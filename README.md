# PrettyGoodPasswords

PrettyGoodPasswords is an application using Google App
Engine. Users can read & write password entries safely and securely. 
Entries are stored in App Engine (NoSQL) High Replication Datastore (HRD).
The master password is hashed with PBKDF2 and a cost factor of 100000.
The private key is generated from PBKDF2 using the master password+salt and
100000 iterations. All site, username, password, and note data is AES encoded
with that private key. The key is kept in a secure, server side session and is
discarded when the user logs out or time expires.

## Site
- [PrettyGoodPasswords][9]

## Products
- [App Engine][1]

## Language
- [Python][2]

## APIs
- [NDB Datastore API][3]
- [Users API][4]

## Dependencies
- [webapp2][5]
- [jinja2][6]
- [Twitter Bootstrap][7]
- [pycrypto][8]

[1]: https://developers.google.com/appengine
[2]: https://python.org
[3]: https://developers.google.com/appengine/docs/python/ndb/
[4]: https://developers.google.com/appengine/docs/python/users/
[5]: http://webapp-improved.appspot.com/
[6]: http://jinja.pocoo.org/docs/
[7]: http://twitter.github.com/bootstrap/
[8]: https://pypi.python.org/pypi/pycrypto
[9]: https://prettygoodpasswords.com

