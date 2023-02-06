from threading import Thread

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags


def send_email(app, template, subject, context, target, thread=True):
    if not thread:
        new_thread = Thread(
            target=send_email,
            kwargs={
                "app": app,
                "template": template,
                "subject": subject,
                "context": context,
                "target": target,
                "thread": True,
            }
        )
        new_thread.start()
    if thread:
        html_content = render_to_string(f"{app}/emails/{template}.html", context)
        text_content = strip_tags(html_content)
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.EMAIL_HOST_USER,
            to=[target]
        )
        email.attach_alternative(html_content, 'text/html')
        email.send()
