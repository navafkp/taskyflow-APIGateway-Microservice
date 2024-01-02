from django.urls import path
from .views import RouteUser,Getaccess, RegisterUser,UserProfile, ColumnsActions,CreateMeeting,CommentAction, GetComments, AddAssignee
from .views import UserUpdate,GetUsers,BlockUser,Notification, BoardAction,CardAction, GetMeeting
from .views import AssigneeDeleteion, CardDeleteion, CardEditUpdate, DeleteBoard, DeleteMeeting

urlpatterns = [ 
    path('user/', RouteUser.as_view(), name='user'),
    path('user/access/', Getaccess.as_view(), name='user_access'),
    path('user/register/', RegisterUser.as_view(), name='user_register'),
    path('user/profile/', UserProfile.as_view(), name='user_profile'),
    path('user/update/', UserUpdate.as_view(), name='user_update'), 
    path('user/users-list/', GetUsers.as_view(), name='get_user_list'),
    path('user/action/<int:id>/', BlockUser.as_view(), name='block_user'),
    path('user/notification/', Notification.as_view(), name='all_notification'),
    path('boards/', BoardAction.as_view(), name="create_get_board"),
    path('board/delete/<str:id>/', DeleteBoard.as_view(), name="delete_board"),
    path('boards/columns/', ColumnsActions.as_view(), name="create_get_columns"),
    path('card/', CardAction.as_view(), name="create_get_card"),
    path('card/assignee/<int:id>/', AssigneeDeleteion.as_view(), name="delete_card_assignee"),
    path('card/assignee/invite/', AddAssignee.as_view(), name="add_card_assignee"),
    path('card/delete/<int:id>/', CardDeleteion.as_view(), name="delete_card"),
    path('card/comment/', GetComments.as_view(), name="get_comment"),
    path('card/comment/<int:id>/', CommentAction.as_view(), name="comment_actions"),
    path('card/card-update/', CardEditUpdate.as_view(), name="edit_card_update"),
    path('meeting/create-meeting/', CreateMeeting.as_view(), name="create_meeting"),
    path('meeting/', GetMeeting.as_view(), name="meeting_actions"),
    path('meeting/delete/<str:id>/', DeleteMeeting.as_view(), name="delete_meeting_actions"),

]
 
 
 
  # path('admin/', RouteAdmin.as_view(), name='admin'),
    # path('admin/access/', GetaccessAdmin.as_view(), name='admin_access'),