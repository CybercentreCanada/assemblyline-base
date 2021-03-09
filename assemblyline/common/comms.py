import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from notifications_python_client.notifications import NotificationsAPIClient
from textwrap import dedent

from assemblyline.common import forge

config = forge.get_config()


def send_email(title: str, message: str, to: str):
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


def send_reset_email(to: str, reset_id: str):
    if config.auth.internal.signup.notify.base_url is not None:
        nc = NotificationsAPIClient(config.auth.internal.signup.notify.api_key,
                                    base_url=config.auth.internal.signup.notify.base_url)
        nc.send_email_notification(to, config.auth.internal.signup.notify.password_reset_template,
                                   personalisation={"fqdn": config.ui.fqdn, "reset_id": reset_id})
    else:
        message = dedent(f"""   
        We have received a request to have your password reset for {config.ui.fqdn}.
        
        To reset your password, please visit the link below: 
        
        https://{config.ui.fqdn}/?reset_id={reset_id}
        
        If you did not make this request, you can safely ignore this email and your password will remain the same.
        """)

        title = f"Assemblyline password reset request for {config.ui.fqdn}"

        send_email(title, message, to)


def send_signup_email(to: str, registration_key: str):
    if config.auth.internal.signup.notify.base_url is not None:
        nc = NotificationsAPIClient(config.auth.internal.signup.notify.api_key,
                                    base_url=config.auth.internal.signup.notify.base_url)
        nc.send_email_notification(to, config.auth.internal.signup.notify.registration_template,
                                   personalisation={"fqdn": config.ui.fqdn, "registration_key": registration_key})
    else:
        message = dedent(f"""
        We have received your request to register for {config.ui.fqdn}.
        
        To confirm your account registration, please visit the link below: 
        
        https://{config.ui.fqdn}/?registration_key={registration_key}
        
        If you did not make this request, you can safely ignore this email.
        """)

        title = f"Confirm your Assemblyline account registration for {config.ui.fqdn}"

        send_email(title, message, to)


def send_authorize_email(to: str, user: str, email: str):
    if config.auth.internal.signup.notify.base_url is not None:
        nc = NotificationsAPIClient(config.auth.internal.signup.notify.api_key,
                                    base_url=config.auth.internal.signup.notify.base_url)
        nc.send_email_notification(to, config.auth.internal.signup.notify.authorization_template,
                                   personalisation={"fqdn": config.ui.fqdn, "user": user, "email": email})
    else:
        message = dedent(f"""
        The following user has created an account and is waiting that his account gets activated.
        
        User: {user}
        Email: {email}
        
        You can browse to the link below to activate the account:
        https://{config.ui.fqdn}/admin/users?query=is_active%3Afalse
        """)

        title = f"A new {config.ui.fqdn} user is waiting for your authorization"

        send_email(title, message, to)


def send_activated_email(to: str, user: str, email: str, admin: str):
    if config.auth.internal.signup.notify.base_url is not None:
        nc = NotificationsAPIClient(config.auth.internal.signup.notify.api_key,
                                    base_url=config.auth.internal.signup.notify.base_url)
        nc.send_email_notification(to, config.auth.internal.signup.notify.activated_template,
                                   personalisation={"fqdn": config.ui.fqdn, "user": user,
                                                    "admin": admin, "email": email})
    else:
        message = dedent(f"""
        The following account was activated on {config.ui.fqdn}.
        
        Username: {user}
        Email: {email}

        The account was activated by: {admin}
        
        Login at https://{config.ui.fqdn}/
        """)

        title = f"Account for {user} now active on {config.ui.fqdn}"

        send_email(title, message, to)
