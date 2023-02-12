
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('',views.home),
    path('signup',views.signup),
    path('activate/<uidb64>/<token>',views.ActivateAccountView.as_view(),name='activate'),
    path('login',views.handleLogin),
    path('logout',views.handlelogout),
    path('request-reset-email',views.RequestResetEmailView.as_view(),name='request-reset-email'),
    path('set-new-password/<uidb64>/<token>',views.SetNewPasswordView.as_view(),name='set-new-password'),
    path('contact',views.contact),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)