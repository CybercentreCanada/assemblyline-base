import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from textwrap import dedent

from assemblyline.common import forge
config = forge.get_config()


def send_email(title, message, to):
    # set up the SMTP server
    s = smtplib.SMTP(host=config.auth.internal.signup.smtp.host, port=config.auth.internal.signup.smtp.port)
    if config.auth.internal.signup.smtp.tls:
        s.starttls()
    s.login(config.auth.internal.signup.smtp.user, config.auth.internal.signup.smtp.password)

    # For each contact, send the email:
    msg = MIMEMultipart()  # create a message

    # setup the parameters of the message
    msg['From'] = config.auth.internal.signup.smtp.from_adr
    msg['To'] = to
    msg['Subject'] = title

    # add in the message body
    msg.attach(MIMEText(message, 'plain'))

    text = msg.as_string()
    s.sendmail(config.auth.internal.signup.smtp.from_adr, to, text)

    # Terminate the SMTP session and close the connection
    s.quit()


def send_reset_email(to, reset_id):
    # add in the actual person name to the message template
    message = dedent("""
    Follow the link bellow to reset your password on {fqdn}:
    
    https://{fqdn}/reset.html?reset_id={reset_id}
    
    If you did not request for a password reset, ignore and delete this email and your password will remain the same.
    """.format(fqdn=config.ui.fqdn, reset_id=reset_id))

    title = "Reset password request for %s" % config.ui.fqdn

    send_email(title, message, to)


def send_signup_email(to, registration_key):
    # add in the actual person name to the message template
    message = dedent("""
    Follow this link to complete your request for user registration on {fqdn}:
    
    https://{fqdn}/login.html?registration_key={registration_key}
    
    If you did not request any account to be created, ignore and delete this email.
    """ .format(fqdn=config.ui.fqdn, registration_key=registration_key))

    title = "User creation request for %s" % config.ui.fqdn

    send_email(title, message, to)
