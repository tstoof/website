# frontend/views.py
from django.shortcuts import render, redirect, get_object_or_404
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
from axes.models import AccessAttempt
from django.conf import settings
from django.utils import timezone
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

            # Check if the user has exceeded the max failed attempts and if they are locked out
            failed_attempts = AccessAttempt.objects.filter(username=user.username).count()
            if failed_attempts > 0:
                last_failed_time = AccessAttempt.objects.filter(username=user.username).last().attempt_time
                time_diff = timezone.now() - last_failed_time
                
                # Check if the lockout period has expired
                if failed_attempts >= settings.AXES_FAILURE_LIMIT and time_diff.total_seconds() < settings.AXES_COOLOFF_TIME * 60:
                                     
                    # Inform the user that their account is locked and they need to wait
                    messages.error(request, f"Your account is temporarily locked due to too many failed login attempts. Please try again in {settings.AXES_COOLOFF_TIME} minutes.")
                    return redirect('locked_out')  # Redirect to your custom lockout page
                if time_diff.total_seconds() < settings.AXES_COOLOFF_TIME * 60:
                    # Proceed to login if not locked out
                    return redirect('locked_out')
            login(request, user)
            return redirect('index')  # Redirect to the homepage after successful login

        else:
            # If the form is not valid (wrong credentials), show a generic error message
            messages.error(request, "Invalid login attempt. Please check your username and password.")

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
    return render(request, 'frontend/index.html', {'username': request.user.username})

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
        form = CustomUserCreationForm(request.POST)
        secret_question_form = SecretQuestionForm(request.POST, is_registration=True)

        if form.is_valid() and secret_question_form.is_valid():
            # Save user
            user = form.save()

            # Save secret question
            question = secret_question_form.cleaned_data['question']
            answer = secret_question_form.cleaned_data['answer']
            SecretQuestion.objects.create(user=user, question=question, answer=answer)
            login(request, user)
            return redirect('index')
    else:
        form = CustomUserCreationForm()
        secret_question_form = SecretQuestionForm(is_registration=True)

    return render(request, 'frontend/signup.html', {
        'form': form,
        'secret_question_form': secret_question_form,
    })


from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from .forms import ResetPasswordForm, SecretQuestionForm
from .models import SecretQuestion

def reset_password(request):
    secret_question = None
    user = None

    if request.method == 'POST':
        form = ResetPasswordForm(request.user, request.POST)
        secret_question_form = SecretQuestionForm(request.POST, is_registration=False)
        
        if form.is_valid() and secret_question_form.is_valid():
            # Validate the secret answer
            username = secret_question_form.cleaned_data.get('username')
            answer = secret_question_form.cleaned_data.get('answer')
            try:
                user = User.objects.get(username=username)
                secret_question = SecretQuestion.objects.get(user=user)
                if secret_question.answer != answer:
                    error_message = "Invalid username or secret question."
                    return render(request, 'frontend/reset_password.html', {
                        'form': ResetPasswordForm(),
                        'secret_question_form': SecretQuestionForm(),
                        'error_message': error_message,
                    })
                    # secret_question_form.add_error('answer', 'Incorrect answer to the secret question.')
                else:
                    # Save the new password
                    form.user = user  # Assign the user to the password form
                    form.save()
                    return redirect('login')
            except (User.DoesNotExist, SecretQuestion.DoesNotExist):
                error_message = "Invalid username or secret question."
                return render(request, 'frontend/reset_password.html', {
                    'form': ResetPasswordForm(),
                    'secret_question_form': SecretQuestionForm(),
                    'error_message': error_message,
                })
                # secret_question_form.add_error('username', 'Invalid username or secret question.')

    else:
        username = request.GET.get('username')
        if username:
            try:
                user = User.objects.get(username=username)
                secret_question = SecretQuestion.objects.get(user=user)
            except (User.DoesNotExist, SecretQuestion.DoesNotExist):
                error_message = "Invalid username or secret question."
                return render(request, 'frontend/reset_password.html', {
                    'form': ResetPasswordForm(),
                    'secret_question_form': SecretQuestionForm(),
                    'error_message': error_message,
                })

        form = ResetPasswordForm(None)
        secret_question_form = SecretQuestionForm(initial={
            'username': username,
            'question': secret_question.question if secret_question else '',
        }, is_registration=False)

    return render(request, 'frontend/reset_password.html', {
        'form': form,
        'secret_question_form': secret_question_form,
        'secret_question': secret_question,
        'error_message':None,
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


@login_required
@csrf_exempt
def edit_route(request, route_id):
    try:
        # Fetch the route for the current user
        route = get_object_or_404(RouteData, id=route_id, user=request.user)
    except RouteData.DoesNotExist:
        logger.error(f"Route with id {route_id} does not exist or doesn't belong to the user")
        return JsonResponse({'error': 'Route not found or permission denied'}, status=404)

    if request.method == 'POST':
        try:
            # Get the new route name from the request body
            data = json.loads(request.body)
            route_name = data.get('route_name')

            if not route_name:
                return JsonResponse({'error': 'Route name is required'}, status=400)

            # Update the route's name
            route.name = route_name
            route.save()

            return JsonResponse({'status': 'success', 'message': 'Route updated successfully'})

        except json.JSONDecodeError:
            logger.error(f"Invalid JSON data received for route {route_id}")
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            logger.error(f"Error updating route {route_id}: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)

    else:
        return JsonResponse({'error': 'Invalid request method. Use POST.'}, status=405)

# Delete Route function
@login_required
@csrf_exempt
def delete_route(request, route_id):
    try:
        # Fetch the route for the current user
        route = get_object_or_404(RouteData, id=route_id, user=request.user)
    except RouteData.DoesNotExist:
        logger.error(f"Route with id {route_id} does not exist or doesn't belong to the user")
        return JsonResponse({'error': 'Route not found or permission denied'}, status=404)

    if request.method == 'POST':
        try:
            # Delete the route from the database
            route.delete()
            return JsonResponse({'status': 'success', 'message': 'Route deleted successfully'})
        except Exception as e:
            logger.error(f"Error deleting route {route_id}: {str(e)}")
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method. Use POST.'}, status=405)
    


def locked_out_view(request):
    return render(request, 'frontend/locked_out.html')