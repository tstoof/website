# frontend/urls.py
from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views  # Import Django's auth views

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('open/', views.open_routeplanner, name='open_routeplanner'),
    path('personal_home/', views.personal_home, name='personal_home'),  # Personal homepage URL
    path('logout/', views.logout_view, name='logout'),
    path('history/', views.history, name='history'),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('personal_routeplanner/', views.personal_routeplanner, name="personal_routeplanner"),
    # path('reset_password/', views.reset_password, name='reset_password'),

    # route api
    path('api/coordinates/', views.receive_coordinates, name='receive_coordinates'),
    path('save_route/', views.save_route, name='save_route'),
    path('load_routes/', views.load_routes, name='load_routes'),
    path('edit_route/<int:route_id>/', views.edit_route, name='edit_route'),
    path('delete_route/<int:route_id>/', views.delete_route, name='delete_route'),
    path('locked_out/', views.locked_out_view, name='locked_out'),
    path('secret_answer_login/', views.secret_answer_login, name='secret_answer_login'),
    path('password_reset/', views.password_reset, name='password_reset'),

]
