from django.contrib.auth.models import User
from django.shortcuts import render
from firebase_admin import auth
from rest_framework import mixins, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import serializers
from firebase_admin import auth
from firebase_admin import credentials
import firebase_admin
from django.contrib.auth import authenticate

cred = credentials.Certificate(
    "fir-ae42b-firebase-adminsdk-2yapl-6fb1688ad1.json")
default_app = firebase_admin.initialize_app(cred)


class SocialLoginSerializer(serializers.Serializer):
    model = User
    fields = []

# Create your views here.


def Firebase_validation(id_token):
    """
   This function receives id token sent by Firebase and
   validate the id token then check if the user exist on
   Firebase or not if exist it returns True else False
   """
    try:
        decoded_token = auth.verify_id_token(id_token)
        # print(decoded_token, "Decoded Token ...................")
        uid = decoded_token['uid']
        # print(uid, "UID......................................")
        provider = decoded_token['firebase']['sign_in_provider']
        identities = decoded_token['firebase']['identities']
        values = list(identities.values())
        identity_id = values[0][0]
        full_name = decoded_token.get("name")

        # print(provider, "Provider..........")
        image = None
        name = None
        if "name" in decoded_token:
            name = decoded_token['name']
            # print(name, "Namee Inside If...................")

        if "picture" in decoded_token:
            image = decoded_token['picture']
            # print(image, "Imageee Inside If...................")
        try:
            user = auth.get_user(uid)
            email = user.email
            if user:
                return {
                    "status": True,
                    "uid": uid,
                    "email": email,
                    "name": name,
                    "provider": provider,
                    "image": image
                }
            else:
                return False
        except auth.UserNotFoundError:
            print("user not exist")
    except auth.ExpiredIdTokenError:
        print("invalid token")


class SocialSignupAPIView(mixins.CreateModelMixin, generics.GenericAPIView):
    """
   api for creating user from social logins
   """
    permission_classes = (AllowAny,)
    serializer_class = SocialLoginSerializer

    def post(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header:
            id_token = auth_header.split(' ').pop()
            print(id_token, "ID token...........")
            validate = Firebase_validation(id_token)

            if validate:
                user = User.objects.filter(username=validate['uid']).first()

                # user = authenticate(username=validate['uid'])
                print(user, "User...............................................")
                # if full_name:
                #     full_name_split = full_name.split(" ")
                #     profile.first_name = full_name_split[0]
                #     profile.last_name = full_name_split[1] if len(full_name_split) > 1 else full_name_split[0]
                #     setattr(profile, "fullname", full_name)

                if user:
                    data = {
                        'id': user.id,
                        'email': user.email,
                        # 'name': user.name,
                        # 'image': user.image,
                        'type': 'existing_user',
                        'provider': validate['provider'],
                    }
                    return Response({'data': data,
                                     'message': 'Login Successful'})
                else:
                    user = User(email=validate['email'],
                                # name=validate['name'], 
                                # uid=validate['uid'],
                                # image=validate['image']
                                )
                    user.save()
                    data = {
                        'id': user.id,
                        'email': user.email,
                        # 'name': user.name,
                        # 'image': user.image,
                        'type': 'new_user',
                        'provider': validate['provider'],
                    }
                return Response({'data': data,
                                 'message': 'User Created Successfully'})
            else:
                return Response({'message': 'invalid token'})
        else:
            return Response({'message': 'token not provided'})
