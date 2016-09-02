# using SendGrid's Python Library - https://github.com/sendgrid/sendgrid-python
import sendgrid
from sendgrid.helpers import mail
from constants import *

def send(_from_email, _to_email, subject, _body_plain, _body_html):
    """
    :param _from_email: string email address
    :param _to_email: string email address
    :param subject: string email subject
    :param _body_plain: string email body
    :param _body_html: string email body with html markup
    :return: response from SendGrid mail client
    """
    sg = sendgrid.SendGridAPIClient(apikey=SENDGRID_API_KEY)
    to_email = mail.Email(_to_email)
    from_email = mail.Email(_from_email)
    #content = mail.Content('text/plain', _body_plain)
    content = mail.Content('text/html', _body_html)
    message = mail.Mail(from_email, subject, to_email, content)
    response = sg.client.mail.send.post(request_body=message.get())
    return response
