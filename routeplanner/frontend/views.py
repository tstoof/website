# frontend/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from domain.functions import *
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib import messages
from django.contrib.auth import get_user_model
from .forms import CustomUserCreationForm
from django.contrib.auth.forms import PasswordChangeForm
from .forms import SecretQuestionForm, ResetPasswordForm
from .models import SecretQuestion
from django.contrib import messages
from django.http import Http404
from .models import RouteData

User = get_user_model()

# Home page view (this is your frontpage)
def index(request):
    return render(request, 'frontend/index.html')

# Login page view
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('personal_home')  # Redirect to route planner after login
    else:
        form = AuthenticationForm()
    return render(request, 'frontend/login.html', {'form': form})

# Open route planner (accessible without login)
def open_routeplanner(request):
    return render(request, 'frontend/open_routeplanner.html')


@csrf_exempt
def receive_coordinates(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse the incoming JSON data
            marker1_lat = data.get('marker1').get('lat')
            marker1_lng = data.get('marker1').get('lng')
            marker2_lat = data.get('marker2').get('lat')
            marker2_lng = data.get('marker2').get('lng')

            coord1 = (marker1_lng, marker1_lat)
            coord2 = (marker2_lng, marker2_lat)
            route = plan_route(coord1, coord2)
            # Store in the session
            request.session["route"] = route

            return JsonResponse({"status": "success", "line_data": route, "route":request.session["route"]})
        except Exception as e:
            print(f"Error in POST: {e}")  # Debugging line
            return JsonResponse({"status": "error", "message": str(e)}, status=400)


# Personal homepage view
@login_required
def personal_home(request):
    # The request.user will give the logged-in user object
    return render(request, 'frontend/personal_home.html', {'username': request.user.username})

def logout_view(request):
    if request.method == 'POST':
        print("Logging out user:", request.user.username)
        logout(request)
        print("Logging out user:", request.user.username)
        return redirect('index')  # Redirect to home page after logout
    return render(request, 'frontend/logout_confirmation.html')

@login_required
def history(request):
    return render(request, 'frontend/history.html', {'username': request.user.username})

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        user.delete()  # This deletes the user account from the database
        messages.success(request, "Your account has been deleted successfully.")
        return redirect('index')  # Redirect to the homepage after deletion
    return render(request, 'frontend/delete_account.html')

@login_required
def personal_routeplanner(request):
    return render(request, 'frontend/personal_routeplanner.html')


def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        secret_question_form = SecretQuestionForm(request.POST, is_registration=True)

        if form.is_valid() and secret_question_form.is_valid():
            # Save user
            user = form.save()

            # Save secret question
            question = secret_question_form.cleaned_data['question']
            answer = secret_question_form.cleaned_data['answer']
            SecretQuestion.objects.create(user=user, question=question, answer=answer)

            return redirect('open_routeplanner')
    else:
        form = UserCreationForm()
        secret_question_form = SecretQuestionForm(is_registration=True)

    return render(request, 'frontend/signup.html', {
        'form': form,
        'secret_question_form': secret_question_form,
    })


def reset_password(request):
    secret_question = None

    if request.method == 'POST':
        form = SecretQuestionForm(request.POST, is_registration=False)

        if form.is_valid():
            # Save the new password
            form.save()

            return redirect('login')
    else:
        username = request.GET.get('username')
        if username:
            try:
                user = User.objects.get(username=username)
                secret_question = SecretQuestion.objects.get(user=user)
            except (User.DoesNotExist, SecretQuestion.DoesNotExist):
                pass

        form = SecretQuestionForm(initial={
            'username': username,
            'question': secret_question.question if secret_question else '',
        }, is_registration=False)

    return render(request, 'frontend/reset_password.html', {
        'form': form,
        'secret_question': secret_question,
    })

@login_required
def load_routes(request):
    if request.method == 'GET':
        routes = RouteData.objects.filter(user=request.user)
        route_list = [
            {'id': route.id, 'name': route.name, 'data': route.data, 'created_at': route.created_at}
            for route in routes
        ]
        return JsonResponse({'routes': route_list})

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@login_required
def save_route(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse the incoming JSON data
            route_name = data.get('name')
            route_data = data.get('data')

            if not route_name or not route_data:
                return JsonResponse({'error': 'Missing route name or data'}, status=400)

            # Create and save the new route
            route = RouteData(user=request.user, name=route_name, data=route_data)
            route.save()

            return JsonResponse({'message': 'Route saved successfully!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)
