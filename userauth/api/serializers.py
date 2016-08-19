from django.contrib.contenttypes.models import ContentType
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from rest_framework import settings

from rest_framework.serializers import (
	EmailField,
	CharField,
	ModelSerializer,
	HyperlinkedIdentityField,
	SerializerMethodField,
	ValidationError,

	)
from rest_framework import serializers, exceptions



User=get_user_model()

class PasswordChangeSerializer(serializers.Serializer):

    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = getattr(
            settings, 'OLD_PASSWORD_FIELD_ENABLED', False
        )
        self.logout_on_password_change = getattr(
            settings, 'LOGOUT_ON_PASSWORD_CHANGE', False
        )
        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop('old_password')

        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            raise serializers.ValidationError('Invalid password')
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()
        if not self.logout_on_password_change:
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(self.request, self.user)




class UserDetailSerializer(ModelSerializer):
	class Meta:
		model =User
		fields = [
			'username',
			'email',
			'first_name',
			'last_name',
		]

class UserForgetPasswordSerializer(ModelSerializer):
	email = EmailField(label='Email Address')
	class Meta:
		model = User
		fields =[
			'username',
			'email',
			'password'
			# 'Confirm_password'
		]

	def forget(self, validated_data):
		username = validated_data.get("username",None)
		email = validated_data.get["email",None]
		password = validated_data['password']
		User.objects.filter(username=username, email=email).update(
			password =password
			)		
		return validated_data						



class UserCreateSerializer(ModelSerializer):
	email = EmailField(label='Email Address')
	email2 = EmailField(label='Confirm Email')
	class Meta:
		model = User
		fields =[
			'username',
			'email',
			'email2',
			'password'
		]
		extra_kwargs = {"password":
							{"write_only":True}

							}

	def validate(self, data):
		# email = data['email']
		# user_qs = User.objects.filter(email=email)
		# if user_qs.exists():
		# 	raise ValidationError("This user has already registered.")
		return data	 

	def validate_email(self, value):
		data = self.get_initial()
		email1 = data.get("email2")
		email2 = value
		if email1 != email2:
			raise ValidationError("Email is must match.")

		user_qs = User.objects.filter(email=email2)
		if user_qs.exists():
			raise ValidationError("This user has already registered.")

		return value

	def validate_email2(self, value):
		data = self.get_initial()
		email1 = data.get("email")
		email2 = value
		if email1 != email2:
			raise ValidationError("Email is must match.")
		return value	

	def create(self, validated_data):
		username = validated_data['username']
		email = validated_data['email']
		password = validated_data['password']
		user_obj = User (
			username = username,
			email = email
			)
		user_obj.set_password(password)			
		user_obj.save()
		return validated_data			

class UserLoginSerializer(ModelSerializer):
	email = EmailField(label='Email Address',allow_blank=True, required=False)
	username = CharField(allow_blank=True, required=False)
	token = CharField(allow_blank=True, read_only=True)
	class Meta:
		model = User
		fields =[
			'username',
			'email', 
			'password',
			'token'
		]
		extra_kwargs = {"password":
							{"write_only":True}

							}

	def validate(self, data):
		user_obj =None
		email = data.get("email",None)
		username = data.get("username",None)
		password = data["password"]
		if not email and not username:
			raise ValidationError("This username or email is required to login.")

		user = User.objects.filter(
				Q(email=email) |
				Q(username=username)
			).distinct()
		# user = user.exclude(email_isnull=True).exclude(email_iexact='')
		if user.exists() and user.count() ==1:
			user_obj = user.first()
		else:
			raise ValidationError("This username/email is not valid.")

		if user_obj:
			if not user_obj.check_password(password):
				raise ValidationError("Incorrect credentials please try again.")

		data["token"] = "SOME RANDOM TOKEN"		
		return data	 		

class PasswordResetSerializer(serializers.Serializer):

    """
    Serializer for requesting a password reset e-mail.
    """

    email = serializers.EmailField()

    password_reset_form_class = PasswordResetForm

    def get_email_options(self):
        """ Override this method to change default e-mail options
        """
        return {}

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return value

    def save(self):
        request = self.context.get('request')
        # Set some values to trigger the send_email method.
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'request': request,
        }

        opts.update(self.get_email_options())
        self.reset_form.save(**opts)	

class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """

    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)

    set_password_form_class = SetPasswordForm

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        self._errors = {}

        # Decode the uidb64 to uid to get User object
        try:
            uid = force_text(uid_decoder(attrs['uid']))
            self.user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise ValidationError({'uid': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs['token']):
            raise ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
        self.set_password_form.save()

# class LoginSerializer(serializers.Serializer):
#     username = serializers.CharField(required=False, allow_blank=True)
#     email = serializers.EmailField(required=False, allow_blank=True)
#     password = serializers.CharField(style={'input_type': 'password'})

#     def _validate_email(self, email, password):
#         user = None

#         if email and password:
#             user = authenticate(email=email, password=password)
#         else:
#             msg = _('Must include "email" and "password".')
#             raise exceptions.ValidationError(msg)

#         return user

#     def _validate_username(self, username, password):
#         user = None

#         if username and password:
#             user = authenticate(username=username, password=password)
#         else:
#             msg = _('Must include "username" and "password".')
#             raise exceptions.ValidationError(msg)

#         return user

#     def _validate_username_email(self, username, email, password):
#         user = None

#         if email and password:
#             user = authenticate(email=email, password=password)
#         elif username and password:
#             user = authenticate(username=username, password=password)
#         else:
#             msg = _('Must include either "username" or "email" and "password".')
#             raise exceptions.ValidationError(msg)

#         return user

#     def validate(self, attrs):
#         username = attrs.get('username')
#         email = attrs.get('email')
#         password = attrs.get('password')

#         user = None

#         if 'allauth' in settings.INSTALLED_APPS:
#             from allauth.account import app_settings

#             # Authentication through email
#             if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
#                 user = self._validate_email(email, password)

#             # Authentication through username
#             if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
#                 user = self._validate_username(username, password)

#             # Authentication through either username or email
#             else:
#                 user = self._validate_username_email(username, email, password)

#         else:
#             # Authentication without using allauth
#             if email:
#                 try:
#                     username = UserModel.objects.get(email__iexact=email).get_username()
#                 except UserModel.DoesNotExist:
#                     pass

#             if username:
#                 user = self._validate_username_email(username, '', password)

#         # Did we get back an active user?
#         if user:
#             if not user.is_active:
#                 msg = _('User account is disabled.')
#                 raise exceptions.ValidationError(msg)
#         else:
#             msg = _('Unable to log in with provided credentials.')
#             raise exceptions.ValidationError(msg)

#         # If required, is the email verified?
#         if 'rest_auth.registration' in settings.INSTALLED_APPS:
#             from allauth.account import app_settings
#             if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
#                 email_address = user.emailaddress_set.get(email=user.email)
#                 if not email_address.verified:
#                     raise serializers.ValidationError(_('E-mail is not verified.'))

#         attrs['user'] = user
#         return attrs

# class TokenSerializer(serializers.ModelSerializer):
#     """
#     Serializer for Token model.
#     """

#     class Meta:
#         model = TokenModel
#         fields = ('key',)


# class JWTSerializer(serializers.Serializer):
#     """
#     Serializer for JWT authentication.
#     """
#     token = serializers.CharField()
#     user = UserDetailsSerializer()