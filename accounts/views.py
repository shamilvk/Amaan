from django.shortcuts import render, redirect
from .forms import RegistrationForm
from .models import Accounts
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

#verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage , send_mail , EmailMultiAlternatives


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split("@")[0]         
            user = Accounts.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()  
            
            # USER ACTIVATION
            current_site = get_current_site(request)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_verification_email.html',{
                'user'   : user,
                'domain' : current_site,
                'uid' :   urlsafe_base64_encode(force_bytes(user.pk)),
                'token'  : default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMultiAlternatives(mail_subject, 'this is the message','muhammadshamil500@gmail.com',['dhruvsudhir123@gmail.com'])
            send_email.send()
            messages.success(request, 'Registration successful.')
            return redirect('register')
    else:                     
        form = RegistrationForm()    
    context = {
        'form' : form,
    }
    return render(request, 'accounts/register.html',context)

send_mail(
    'Subject here',
    'Here is the message.',
    'muhammadshamil500@gmail.com',
    ['dhruvsudhir123@gmail.com'],
    fail_silently=False,
)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        
        user = auth.authenticate(email=email, password=password)
        
        if user is not None:
            auth.login(request, user)
            # messages.success(request, 'You are now logged in.')
            return redirect('home')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')

@login_required(login_url = 'login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You are logged out.')
    return redirect('login')

def activate(request , uidb64, token):
    return  HttpResponse('ok')