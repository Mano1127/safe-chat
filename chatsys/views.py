import pyrebase
import datetime
import pytz
import nltk
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from .forms import SignUpForm

# NLTK Sentiment Analysis
from nltk.classify import NaiveBayesClassifier
from nltk.sentiment import SentimentAnalyzer
from nltk.sentiment.util import *
from nltk.sentiment.vader import SentimentIntensityAnalyzer

# Download required datasets
nltk.download('subjectivity')
nltk.download('vader_lexicon')

# Sentiment Analysis Training (Done once, outside views)
n_instances = 100
subj_docs = [(sent, 'subj') for sent in nltk.corpus.subjectivity.sents(categories='subj')[:n_instances]]
obj_docs = [(sent, 'obj') for sent in nltk.corpus.subjectivity.sents(categories='obj')[:n_instances]]
train_docs = subj_docs + obj_docs
sentim_analyzer = SentimentAnalyzer()
all_words_neg = sentim_analyzer.all_words([mark_negation(doc) for doc in train_docs])
unigram_feats = sentim_analyzer.unigram_word_feats(all_words_neg, min_freq=4)
sentim_analyzer.add_feat_extractor(extract_unigram_feats, unigrams=unigram_feats)
training_set = sentim_analyzer.apply_features(train_docs)
trainer = NaiveBayesClassifier.train
classifier = sentim_analyzer.train(trainer, training_set)
sia = SentimentIntensityAnalyzer()

# Firebase Configuration
firebase_config = {
    "apiKey": "AIzaSyBV-GX50Ec6331WoW31qKMWHeYYSfiuwjk",
    "authDomain": "final-project-e7ed9.firebaseapp.com",
    "databaseURL": "https://final-project-e7ed9-default-rtdb.firebaseio.com",
    "projectId": "final-project-e7ed9",
    "storageBucket": "final-project-e7ed9.appspot.com",
    "messagingSenderId": "271461608417",
    "appId": "1:271461608417:web:5164bd0dabb22342ef80a0"
}

firebase = pyrebase.initialize_app(firebase_config)
db = firebase.database()
auth = firebase.auth()

IST = pytz.timezone('Asia/Kolkata')

# Home View
def home(request):
    data = {}
    if request.user.is_authenticated:
        allusers = {}
        sus_users = db.child("Suspicious_users").child(request.user.username).get().val() or {}
        for u in User.objects.all():
            if u.username not in (request.user.username, "admin") and u.username not in sus_users:
                allusers[u.username] = u.first_name + " " + u.last_name
        data["Users"] = allusers

        if request.method == 'POST':
            receiver = request.POST['receiver']
            data["rec"] = receiver

        return render(request, 'chatsys/chat.html', data)
    else:
        return render(request, 'chatsys/home.html', data)

# Suspicious Users View
def susUsers(request):
    if request.user.is_authenticated:
        data = {}
        allusers = {}
        sus_users = db.child("Suspicious_users").child(request.user.username).get().val() or {}
        for u in User.objects.all():
            if u.username not in (request.user.username, "admin") and u.username in sus_users:
                allusers[u.username] = u.first_name + " " + u.last_name

        data["Users"] = allusers
        data["SUS"] = True

        if not allusers:
            return render(request, 'chatsys/chat.html', data)

        if request.method == 'POST':
            receiver = request.POST['receiver']
            data["rec"] = receiver

            if 'markUnsuspicious' in request.POST:
                db.child("Suspicious_users").child(request.user.username).child(receiver).remove()
                return redirect('/sus_users')

        return render(request, 'chatsys/chat.html', data)
    else:
        return redirect('/')

# Get Messages View
def getMessages(request, rec):
    if request.user.is_authenticated:
        mk = "-".join(sorted([request.user.username, rec]))
        data, chats = {}, {}
        dbchat = db.child("Chats").child(mk).get().val()
        chats = dbchat.values() if dbchat else []
        data["rec"] = rec
        data["Chats"] = zip(chats, [c["Sender"] == request.user.username for c in chats]) if chats else zip({}, [])
        return render(request, 'chatsys/messages.html', data)
    else:
        return redirect('/')

# Send Message View
@csrf_exempt
def sendMessage(request, rec):
    if request.user.is_authenticated and request.method == 'POST':
        mk = "-".join(sorted([request.user.username, rec]))
        message = request.POST['message'].strip()

        if message:
            Datetime = str(datetime.datetime.now(IST))[:-13]
            ss = sia.polarity_scores(message)

            if ss["neg"]:
                db.child("Suspicious_users").child(rec).child(request.user.username).update({"sus_user": True})

            msg = {
                "Sender": request.user.username,
                "Receiver": rec,
                "dateTime": Datetime,
                "Message": message,
                "sus": float(ss["neg"])
            }

            db.child("Chats").child(mk).push(msg)
            return HttpResponse(f"Message Sent to {rec}")
    return redirect('/')

# Sign Up View
@csrf_exempt
def signUp(request):
    if request.user.is_authenticated:
        return redirect('/')
    else:
        if request.method == 'POST':
            form = SignUpForm(request.POST)
            if form.is_valid():
                form.save()
                username = form.cleaned_data['username']
                password = form.cleaned_data['password1']
                user = authenticate(username=username, password=password)
                login(request, user)

                # Fix: Use `username` instead of `request.user`
                db.child("Bio").child(username).update({"bio": "Hello there!"})
                return redirect('/')
        else:
            form = SignUpForm()
        return render(request, 'chatsys/signup.html', {'form': form})

# Log In View
@csrf_exempt
def logIn(request):
    if request.user.is_authenticated:
        return redirect('/')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect('/')
            else:
                messages.error(request, 'Username or Password is Incorrect')
        return render(request, 'chatsys/login.html')

# Log Out View
def logOut(request):
    if request.user.is_authenticated:
        logout(request)
    return redirect('/')

# Profile View
def profile(request):
    if not request.user.is_authenticated:
        return redirect('/login')
    else:
        username = request.user.username
        if request.method == 'POST':
            bio = request.POST['bio']
            db.child("Bio").child(username).update({"bio": bio})
            messages.success(request, 'Bio Updated')

        user_bio = db.child("Bio").child(username).get().val() or {'bio': ""}
        img_url = f"https://avatars.dicebear.com/api/initials/{request.user.first_name}%20{request.user.last_name}.svg"
        
        return render(request, 'chatsys/profile.html', {"bio": user_bio['bio'], "imgurl": img_url})
