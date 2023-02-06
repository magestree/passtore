from rest_framework import serializers
from .models import Passwd, Container


class ContainerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Container


class PasswdSerializer(serializers.ModelSerializer):
    container = ContainerSerializer(many=False)

    class Meta:
        model = Passwd
