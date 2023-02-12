from django.shortcuts import render,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.generic import View
from django.contrib.auth import authenticate, login, logout

# To activate user account
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site 
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from .utils import TokenGenerator,generate_token
from django.utils.encoding import force_bytes,DjangoUnicodeDecodeError,force_str
from django.core.mail import EmailMessage

# Reset Password Generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Email
from django.core.mail import EmailMessage
from django.conf import settings

# Threading
import threading

class EmailThread(threading.Thread):
    
    def __init__(self,email_message):
        self.email_message=email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

        #connection.send_messages(messages)  

# Create your views here.
def home(request):
    return render(request, 'index.html')

def contact(request):
    return render(request,'contact.html')

def signup(request):
    if request.method=="POST":
        fname=request.POST['first_name']
        lname=request.POST['last_name']
        phone_number=request.POST['number']
        email=request.POST['email']
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
      
        if password!=confirm_password:
            messages.warning(request,"Password is Not Matching")
            return render(request,'signup.html') 

        try:
            if User.objects.get(username=phone_number):
                messages.warning(request,'Phone number is already taken')
                return redirect('/signup')
        except Exception as identifier:
            pass          

        try:
            if User.objects.get(email=email):
                messages.warning(request,'Email is already taken')
                return redirect('/signup')
        except Exception as identifier:
            pass    

        user = User.objects.create_user(first_name=fname, last_name=lname, username=phone_number, email=email, password=password)
        user.is_active=False
        user.save()
        current_site=get_current_site(request)
        
        email_subject="Activate Your Account"
        message=render_to_string('activate.html',{
            'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)

        })
        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        email_message.send()
        messages.success(request,"Activate Your Account by clicking the link in your gmail")
        return redirect('/login')
    return render(request,"signup.html")


class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/login')
        return render(request,'activate_fail.html')
  
def handleLogin(request):  
    if request.method=="POST":
        mobile= request.POST.get('number')
        print(mobile)
        password= request.POST.get('pass1')
        print(password)
        myuser=authenticate(username=mobile, password=password)
        print(myuser)
        context={"myuser":myuser}
        if myuser is not None:
            login(request,myuser)
            messages.info(request,'Login Successfull')
            return redirect('/')
            #return render(request,'index.html',context=context)
        else:
            messages.error(request,'Invalid Credentials')
            return redirect('/login')   
    return render(request,'login.html')

def handlelogout(request):
    logout(request)
    messages.success(request,'Logout Successful')
    return redirect('/login')

    
class RequestResetEmailView(View):
    def get(self, request):
        return render(request,'reset_password.html')

    def post(self,request):
        email=request.POST['email']
        user= User.objects.filter(email=email)
        current_site= get_current_site(request)
        email_subject= ['Reset Your Password']
        message=render_to_string('reset_user_password.html',{
            #'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
            'token':PasswordResetTokenGenerator().make_token(user[0])
        })
        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        #email_message.send()
        EmailThread(email_message).start()
        messages.info(request,"We have send you email with instruction how to reset email")
        return render(request,'login.html')


class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,'Password reset link is invalid')
                return render(request,'reset_password.html')
                
        except DjangoUnicodeDecodeError as identifier:
            pass        

        return render(request,'set-new-password.html',context)
    
    def post(self, request, uidb64, token):
        context={
            'uidb64':uidb64,
            'token':token
        }
        password= request.POST.get('pass1')
        confirm_password=request.POST.get('pass2')
        if password != confirm_password:
            messages.warning(request,'Password is not matching')
            return render(request,'set-new-password.html',context)
        
        try:
            user_id= force_str(urlsafe_base64_decode(uidb64))
            user= User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,'Password reset successfully. Please login with new password')
            return redirect('/login')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,'Something went wrong !!! ')
            return render(request,'set-new-password.html',context)


