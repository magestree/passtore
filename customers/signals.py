from django.core.mail import send_mail
from django.db.models.signals import post_save

from customers.models import Customer, RecoverCode
from passtore.settings import SENDER_EMAIL


def send_code_password_reset(sender, instance, **kwargs):
    if kwargs.get('created', True):
        email = instance.email
        try:
            username = Customer.objects.filter(email=email).first()

            subject = 'Passtore: Código de recuperación de contraseña'

            message = f'¡Intentaste iniciar sesión en Passtore! \
                        Hola {username} \
                        ¡Usa tu código secreto! \
                        {instance.code} \
                        Si no olvidó su contraseña, puede ignorar este correo electrónico.'

            send_mail(subject, message, SENDER_EMAIL, [email])
        except Customer.DoesNotExist:
            pass


post_save.connect(send_code_password_reset, sender=RecoverCode, dispatch_uid="send_code_password_reset")
