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
from django.contrib.auth.models import User
from django.utils.timezone import now, timedelta
from axes.models import AccessAttempt
from django.views.decorators.csrf import csrf_protect  # Use csrf_protect if necessary



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
                    return redirect('locked_out')  
                if time_diff.total_seconds() < settings.AXES_COOLOFF_TIME * 60:
                    return redirect('locked_out')
                
            # Successful login, reset failed attempts
            AccessAttempt.objects.filter(username=user.username).delete()  # Delete all failed attempts for this user
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




@csrf_protect  # Ensures CSRF protection for POST requests
def receive_coordinates(request):
    if request.method == 'POST':
        try:
            # Parse and validate the incoming JSON data
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({"status": "error", "message": "Invalid JSON format."}, status=400)

            # Validate required fields exist
            if 'marker1' not in data or 'marker2' not in data:
                return JsonResponse({"status": "error", "message": "Missing required coordinates."}, status=400)

            # Extract coordinates
            marker1 = data['marker1']
            marker2 = data['marker2']
            
            if not all(key in marker1 and key in marker2 for key in ['lat', 'lng']):
                return JsonResponse({"status": "error", "message": "Invalid data structure for coordinates."}, status=400)

            # Validate that latitudes and longitudes are valid numbers and within the correct range
            try:
                marker1_lat = float(marker1['lat'])
                marker1_lng = float(marker1['lng'])
                marker2_lat = float(marker2['lat'])
                marker2_lng = float(marker2['lng'])
            except (ValueError, TypeError):
                return JsonResponse({"status": "error", "message": "Coordinates must be valid numbers."}, status=400)

            if not (-90 <= marker1_lat <= 90) or not (-180 <= marker1_lng <= 180):
                return JsonResponse({"status": "error", "message": "Invalid latitude or longitude for marker 1."}, status=400)
            if not (-90 <= marker2_lat <= 90) or not (-180 <= marker2_lng <= 180):
                return JsonResponse({"status": "error", "message": "Invalid latitude or longitude for marker 2."}, status=400)

            # Process the coordinates and plan the route
            coord1 = (marker1_lng, marker1_lat)
            coord2 = (marker2_lng, marker2_lat)
            route = plan_route(coord1, coord2)  # Assuming 'plan_route' is a trusted function

            # Store the route in the session (validate if necessary)
            # request.session["route"] = route

            return JsonResponse({"status": "success", "line_data": route, "route": route})

        except Exception as e:
            # Log the exception securely and avoid exposing details
            logger.error(f"Error processing coordinates: {str(e)}")
            return JsonResponse({"status": "error", "message": "An unexpected error occurred."}, status=500)



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
            # Clear any failed attempts that may have been erroneously registered
            AccessAttempt.objects.filter(username=user.username).delete()

            # Save secret question
            question = secret_question_form.cleaned_data['question']
            answer = secret_question_form.cleaned_data['answer']
            SecretQuestion.objects.create(user=user, question=question, answer=answer)
            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            return redirect('index')
    else:
        form = CustomUserCreationForm()
        secret_question_form = SecretQuestionForm(is_registration=True)

    return render(request, 'frontend/signup.html', {
        'form': form,
        'secret_question_form': secret_question_form,
    })



@login_required
def load_routes(request):
    if request.method == 'GET':
        cipher_suite = Fernet(settings.ENCRYPTION_KEY)
        routes = RouteData.objects.filter(user=request.user)
        print(routes)
        route_list = []
        for route in routes:
            print(route)
            try:
                decrypted_data = cipher_suite.decrypt(b64decode(route.data)).decode('utf-8')
                route_list.append({
                    'id': route.id,
                    'name': route.name,
                    'data': json.loads(decrypted_data),
                    'created_at': route.created_at
                })
            except Exception as e:
                logger.error(f"Decryption failed for route {route.id}: {str(e)}")
        
        return JsonResponse({'routes': route_list})

    return JsonResponse({'error': 'Invalid request method'}, status=405)

from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
@login_required
def save_route(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse the incoming JSON data
            route_name = data.get('name')
            route_data = data.get('data')

            if not route_name or not route_data:
                return JsonResponse({'error': 'Missing route name or data'}, status=400)
            
            if isinstance(route_data, (list, dict)):
                route_data = json.dumps(route_data)

            cipher_suite = Fernet(settings.ENCRYPTION_KEY)
            # Encrypt the route data
            encrypted_data = cipher_suite.encrypt(route_data.encode())
    
            # Encode the encrypted data in Base64 for JSON compatibility
            encrypted_data_base64 = b64encode(encrypted_data).decode('utf-8')
            
            # Create and save the new route
            route = RouteData(user=request.user, name=route_name, data=encrypted_data_base64)
            route.save()

            return JsonResponse({'message': 'Route saved successfully!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@login_required
@csrf_protect  # Ensures CSRF protection for POST requests
def edit_route(request, route_id):
    try:
        # Fetch the route for the current user
        route = get_object_or_404(RouteData, id=route_id, user=request.user)
    except RouteData.DoesNotExist:
        logger.warning(f"Route with id {route_id} does not exist or doesn't belong to the user")
        return JsonResponse({'error': 'Route not found or permission denied'}, status=404)

    if request.method == 'POST':
        try:
            # Get the new route name from the request body
            data = json.loads(request.body)

            # Validate route_name input
            route_name = data.get('route_name')
            if not route_name:
                return JsonResponse({'error': 'Route name is required'}, status=400)
            
            # Ensure the route name is a valid string (e.g., no special characters)
            if not isinstance(route_name, str) or len(route_name.strip()) == 0:
                return JsonResponse({'error': 'Route name must be a valid non-empty string'}, status=400)

            # Optionally, you can add a length limit for the route name
            if len(route_name) > 100:  # Example: restrict name length to 100 characters
                return JsonResponse({'error': 'Route name is too long. Maximum length is 100 characters.'}, status=400)

            # Update the route's name
            route.name = route_name
            route.save()

            return JsonResponse({'status': 'success', 'message': 'Route updated successfully'})

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON data received for route {route_id}")
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            logger.error(f"Error updating route {route_id}: {str(e)}")
            return JsonResponse({'error': 'An error occurred while processing your request'}, status=400)

    else:
        return JsonResponse({'error': 'Invalid request method. Use POST.'}, status=405)


# Delete Route function
@login_required
@csrf_protect
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




# def reset_password(request):
#     secret_question = None
#     user = None

#     if request.method == 'POST':
#         form = ResetPasswordForm(request.user, request.POST)
#         secret_question_form = SecretQuestionForm(request.POST, is_registration=False)
        
#         if form.is_valid() and secret_question_form.is_valid():
#             # Validate the secret answer
#             username = secret_question_form.cleaned_data.get('username')
#             answer = secret_question_form.cleaned_data.get('answer')
#             try:
#                 user = User.objects.get(username=username)
#                 secret_question = SecretQuestion.objects.get(user=user)
#                 if secret_question.answer != answer:
#                     error_message = "Invalid username or secret question."
#                     return render(request, 'frontend/reset_password.html', {
#                         'form': ResetPasswordForm(),
#                         'secret_question_form': SecretQuestionForm(),
#                         'error_message': error_message,
#                     })
#                 else:
#                     # Save the new password
#                     form.user = user  # Assign the user to the password form
#                     form.save()
#                     return redirect('login')
#             except (User.DoesNotExist, SecretQuestion.DoesNotExist):
#                 error_message = "Invalid username or secret question."
#                 return render(request, 'frontend/reset_password.html', {
#                     'form': ResetPasswordForm(),
#                     'secret_question_form': SecretQuestionForm(),
#                     'error_message': error_message,
#                 })

#     else:
#         username = request.GET.get('username')
#         if username:
#             try:
#                 user = User.objects.get(username=username)
#                 secret_question = SecretQuestion.objects.get(user=user)
#             except (User.DoesNotExist, SecretQuestion.DoesNotExist):
#                 error_message = "Invalid username or secret question."
#                 return render(request, 'frontend/reset_password.html', {
#                     'form': ResetPasswordForm(),
#                     'secret_question_form': SecretQuestionForm(),
#                     'error_message': error_message,
#                 })

#         form = ResetPasswordForm(None)
#         secret_question_form = SecretQuestionForm(initial={
#             'username': username,
#             'question': secret_question.question if secret_question else '',
#         }, is_registration=False)

#     return render(request, 'frontend/reset_password.html', {
#         'form': form,
#         'secret_question_form': secret_question_form,
#         'secret_question': secret_question,
#         'error_message':None,
#     })


from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth import login, authenticate
from django.shortcuts import render, redirect
from .models import SecretQuestion
from .forms import SecretAnswerLoginForm
from django.contrib.auth.backends import ModelBackend

def secret_answer_login(request):
    error_message = None

    if request.method == 'POST':
        form = SecretAnswerLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            secret_answer = form.cleaned_data['secret_answer']

            try:
                user = User.objects.get(username=username)
                secret_question = SecretQuestion.objects.get(user=user)

                # Ensure the hash is valid
                if not secret_question.answer.startswith('pbkdf2_sha256$'):
                    print("Hash is invalid or missing. Rehashing...")
                    secret_question.answer = make_password(secret_question.answer)
                    secret_question.save()
                

                # Check password
                if check_password(secret_answer, secret_question.answer):
                    # Authenticate and log in user
                    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                    return redirect('password_reset')
                    # authenticated_user = authenticate(request, username=user.username, password=None)
                    # if authenticated_user:
                    #     print("yes")
                    #     login(request, authenticated_user)
                    #     return redirect('password_reset')
                    # else:
                        # error_message = "Authentication failed. Please try again."
                else:
                    error_message = "Invalid secret answer. Please try again."
            except User.DoesNotExist:
                error_message = "User does not exist."
            except SecretQuestion.DoesNotExist:
                error_message = "No secret question set for this user."
        else:
            error_message = "Form is invalid. Please check the inputs."

    else:
        form = SecretAnswerLoginForm()

    return render(request, 'frontend/secret_answer_login.html', {
        'form': form,
        'error_message': error_message,
    })


from django.contrib.auth.decorators import login_required
from .forms import ResetPasswordForm

@login_required
def password_reset(request):
    if request.method == 'POST':
        form = ResetPasswordForm(request.user, request.POST)
        if form.is_valid():
            # Set the new password
            request.user.set_password(form.cleaned_data['new_password1'])
            request.user.save()
            return redirect('login')  # Redirect to login after successful reset
    else:
        form = ResetPasswordForm(request.user)

    return render(request, 'frontend/password_reset.html', {'form': form})
