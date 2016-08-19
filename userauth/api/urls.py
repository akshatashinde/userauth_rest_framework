from django.conf.urls import url
from django.contrib import admin

from .views import (
    UserCreateAPIView,
    UserLoginAPIView,
    PasswordResetView,
    PasswordChangeView,
    LogoutView,
    PasswordResetView,
    PasswordResetConfirmView,
    # LoginView,
    )

urlpatterns = [
	url(r'^login/$', UserLoginAPIView.as_view() , name='login'),
	# url(r'^login/$', LoginView.as_view(), name='rest_login'),
	url(r'^logout/$', LogoutView.as_view(), name='rest_logout'),
    url(r'^register/$', UserCreateAPIView.as_view() , name='register'),
    url(r'^change/$', PasswordChangeView.as_view() , name='change'),
    url(r'^password/reset/$', PasswordResetView.as_view(),
        name='rest_password_reset'),
    url(r'^password/reset/confirm/$', PasswordResetConfirmView.as_view(),
        name='rest_password_reset_confirm'),

]
