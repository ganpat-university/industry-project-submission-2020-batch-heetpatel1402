from django.urls import path
from . import views

urlpatterns = [
    path('',views.say_hello),
    path('index1/',views.index1, name = "index1"),
    path('learnmore/',views.learnmore, name = "learnmore"),
    path('index1/detect/',views.detect, name = "detect"),
]                                                            