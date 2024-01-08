import json
import requests
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
import jwt
import os, time
from dotenv import load_dotenv
# Load the stored environment variables
load_dotenv()
import uuid, pika, json

admin_url = os.getenv('ADMIN_URL')
user_url = os.getenv('USER_URL')
notification_url = os.getenv('NOTIFICATION_URL')
task_url = os.getenv('TASK_SERVICE_URL')
secret_key = os.getenv('SECRET_KEY')


# Connection parameters
params = pika.ConnectionParameters(
    host='docker-taskyflow-microservice-rabbitmq-container-1',
    port=5672,
    virtual_host='/',
    credentials=pika.PlainCredentials(username='taskyapp', password='1345'),
    heartbeat=600,
)

# creating a connection for rabbit mq
def establish_connection():
    while True:
        try:
            connection = pika.BlockingConnection(params)
            return connection
        except pika.exceptions.AMQPConnectionError:
            time.sleep(10)
            

def tokenSplit(auth_author):
    # get access token with bearer, spilt and return teh access token
    if not auth_author or 'Bearer' not in auth_author:
        raise AuthenticationFailed("Unauthorized User")
    token = auth_author.split('Bearer ')[1]
    return token


def decode_jwt(token):
    # decoding the access token
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("Token has expired")
    except jwt.InvalidSignatureError:
        raise jwt.InvalidSignatureError("Invalid token signature")
    except jwt.DecodeError:
        raise jwt.DecodeError("Error decoding the token")
   
# connecting with user service via rabbit mq and checking whether the user is exist  
def authenticate_user(auth_author, success_callback):
    token = None
    # checking the request data is a dict or not, if yes, need to check with user service whetehr user is manager or not
    if isinstance(auth_author, dict):
        need_confirm_manager = auth_author.get('manager', None)
        auth_author = auth_author.get('auth_author', None)
        if not auth_author or 'Bearer' not in auth_author:
            raise AuthenticationFailed("Unauthorized User")
        token = auth_author.split('Bearer ')[1]
        data = {'access': token, 'manager': 'confirm'}
        data_json = json.dumps(data)
        
    else:
    # authenticating user and return boolean value
        if not auth_author or 'Bearer' not in auth_author:
            raise AuthenticationFailed("Unauthorized User")
        token = auth_author.split('Bearer ')[1]
        data = {'access': token}
        data_json = json.dumps(data)
        
    if token is not None:
        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            headers = {'Content-Type': 'application/json'}
            connection = establish_connection()
            channel = connection.channel()
            
            def on_reply_message_received(ch, method, properties, body):
                data = json.loads(body).get("bool")
                if data == True:
                    success_callback('true')
                else:
                    raise AuthenticationFailed("Authentication failed")
            reply_queue = channel.queue_declare(queue='', exclusive=True)
            reply_to_queue_name = reply_queue.method.queue
            channel.basic_consume(
                queue=reply_to_queue_name,
                on_message_callback=on_reply_message_received,
                auto_ack=True
            )
            
            # Publish the message to RabbitMQ
            correlation_id = str(uuid.uuid4())
            channel.queue_declare(queue='api_gateway', durable=True)
            channel.basic_publish(
                exchange='',
                routing_key='api_gateway',
                properties=pika.BasicProperties(
                    reply_to=reply_to_queue_name,
                    correlation_id=correlation_id,
                ),
                body=data_json
            )
            connection.process_data_events(time_limit=5)
            
        except jwt.exceptions.InvalidSignatureError as e:
            raise AuthenticationFailed("Invalid token signature")
        except jwt.ExpiredSignatureError as e:
            raise AuthenticationFailed("Token has expired")
        except jwt.DecodeError as e:
            print(str(e))
            raise AuthenticationFailed("Error decoding the token") 
    
class RouteUser(APIView):
    def post(self, request):
        """
        Given the details, legin request handled
        """
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            data = {'email': email, 'password': password}
            data_json = json.dumps(data)
            headers = {'Content-Type': 'application/json'} 
            response = requests.post(f'{user_url}/token/', data=data_json, headers=headers)
            
            if response.status_code // 100 == 2:
                data = response.json()
                refresh = data.get('refresh', '')
                access = data.get('access', '')  
                return Response({'access': access, 'refresh':refresh}, status=status.HTTP_200_OK)
            elif response.status_code == 401:
                data = response.json()
                error = data.get('detail', '')
                return Response({"error", error}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"error": "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        except requests.RequestException as e:
            return Response({"error": f"Request Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Internal Server Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
                      
class Getaccess(APIView):
    """Getting access token using refersh token"""
    def post(self, request):
        try:
            data = {'refresh': request.data.get('refresh')}
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f'{user_url}/token/refresh/', json=data, headers=headers)
            
            if response.status_code // 100 == 2:
                data = response.json()
                refresh = data.get('refresh', '')
                access = data.get('access', '')  
                return Response({'access': access, 'refresh':refresh}, status=status.HTTP_200_OK)
            elif response.status_code // 100 == 4:
                data = response.json()
                error = data.get('detail', '')
                return Response({"error", error}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({"error": "Internal Server Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except requests.RequestException as e:
            return Response({"error": f"Request Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"error": f"Internal Server Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
           
class RegisterUser(APIView):
    """ 
    Given Details, registraion completed alog with the user service
    """
    def post(self, request):
        try:
            name = request.data.get('name')
            username = request.data.get('username')
            role = request.data.get('role')
            email = request.data.get('email')
            designation = request.data.get('designation')
            workspace = request.data.get('workspace')
            password = request.data.get('password')
            password2 = request.data.get('password2')
            
            data = {
                'name':name, 
                'username':username, 
                'email': email, 
                'workspace': workspace, 
                'password':password, 
                'password2': password2,
                'role': role,
                'designation':designation,
            }
            data_json = json.dumps(data)
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f'{user_url}/register/', data=data_json, headers=headers)
            data = response.json()
            if response.status_code // 100 == 2:
                return Response(data,  status=status.HTTP_200_OK)
            elif response.status_code // 100 == 4:
                exactError = data.get('error')
                if 'username' in exactError:
                    return Response(data, status=status.HTTP_400_BAD_REQUEST)
                elif 'email' in exactError:
                    return Response(data, status=status.HTTP_409_CONFLICT)
                else:
                    return Response(data,status=status.HTTP_400_BAD_REQUEST)       
            else:
                return Response({'error':'Something went wrong, please try again'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        except requests.RequestException as e:
            return Response({'message': f'Request Error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except Exception as e:
            return Response({'message': f'Internal Server Error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

     
class UserProfile(APIView):
    """ 
    Given details, connecting with the user service and get the logged er data
    """
    def get(self, request):
        token = request.headers.get('authorization')
        if token:
            
            try:
                token = str(token)
                decodePayload = jwt.decode(token, secret_key, algorithms=["HS256"])
                data = {"token":token}
                data_json = json.dumps(data)
                headers = {'Content-Type': 'application/json'}
                response = requests.get(f'{user_url}/user/details/', data=data_json, headers=headers )
                data = response.json()
                return Response(data, status=status.HTTP_200_OK)
           
            except jwt.exceptions.InvalidSignatureError as e:
                return Response({"error": "Invalid token signature"}, status=status.HTTP_401_UNAUTHORIZED)
            except jwt.ExpiredSignatureError as e:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except jwt.DecodeError as e:
                return Response({"error": "Error decoding the token"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"error": "Authorization header not found"}, status=status.HTTP_401_UNAUTHORIZED)
             
class UserUpdate(APIView):
    """ 
    Updating user profile request redirecting to user service
    """
    def patch(self, request):
        user_details = request.data.get('data')
        token = request.data.get('access')
        
        try:
            token = str(token)
            decodePayload = jwt.decode(token, secret_key, algorithms=["HS256"])
            data = {"token": token, 'userdetails':user_details}
            data_json = json.dumps(data)
            headers = {'Content-Type': 'application/json'}
            response = requests.patch(f'{user_url}/user/update/', data=data_json, headers=headers )
            message = response.json()
            return Response(message, status=status.HTTP_200_OK)
        
        except jwt.exceptions.InvalidSignatureError as e:
            return Response({"error": "Invalid token signature"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError as e:
            return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.DecodeError as e:
            return Response({"error": "Error decoding the token"}, status=status.HTTP_401_UNAUTHORIZED)
        
        
class GetUsers(APIView):
    """ Given details, collected all users data based on workspace"""
    def get(self, request):
        workspace = request.GET.get('workspace')
        auth_header = request.headers.get('authorization')
        if not auth_header or 'Bearer' not in auth_header:
            raise AuthenticationFailed('Not Autherized')
        token = auth_header.split('Bearer ')[1]
        if token:
            try:
                decode_result = jwt.decode(token, secret_key, algorithms=['HS256'] )
                data = {'workspace':workspace, 'token':token}
                data_json = json.dumps(data)
                headers = {'Content-Type': 'application/json'}
                resposne = requests.get(f'{user_url}/user/all-users/', headers=headers, data=data_json)
                data = resposne.text
                return Response(data, status=status.HTTP_200_OK)
            
            except jwt.exceptions.InvalidSignatureError as e:
                return Response({"error": "Invalid token signature"}, status=status.HTTP_401_UNAUTHORIZED)
            except jwt.ExpiredSignatureError as e:
                return Response({"error": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            except jwt.DecodeError as e:
                return Response({"error": "Error decoding the token"}, status=status.HTTP_401_UNAUTHORIZED)
   
      
                          
class BlockUser(APIView):
    """Given the user id, blocked the user"""
    
    def patch(self, request, id=None):
        action = request.data
        auth_author = request.headers.get('authorization')
        token = tokenSplit(auth_author) #spliting the auth_author to get access token
        if token:
            payload = decode_jwt(token) #decoding access token
            data = {'value':action, 'access':token }
            data_json = json.dumps(data)
            headers = {'Content-Type': 'application/json'}
            id = int(id)
            resposne = requests.patch(f'{user_url}/user/action/{id}/', headers=headers, data=data_json)
            data = resposne.text
            return Response(data)
        else:
            return Response({"error": 'Unauthorized Access, Token required'})   
       
class Notification(APIView):
    """Get all notifications based on the workspace after validating the access token"""
    def get(self, request):
        auth_author = request.headers.get('authorization')
        boolean = 'false'
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
 
        authenticate_user(auth_author, success_callback)
        if boolean == 'true':
                headers = {'Content-Type': 'application/json'}
                for_notification_json = json.dumps(request.query_params)
                resposne = requests.get(f'{notification_url}/notification/', data=for_notification_json, headers=headers)
                data = resposne.json()
                return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error":"Unauthorized Access"})
        

 
class BoardAction(APIView):
    
    # given details, created board and 3 columns by default
    def post(self, request):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            board_data_json = json.dumps(request.data)
            resposne = requests.post(f'{task_url}/board/', data=board_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
        
    #  getting all boards data
    def get(self, request):
        boolean = 'false'
        workspace = request.GET.get('workspace')
        auth_author = request.headers.get('authorization')
        # returned_value = authenticate_user(auth_author) #authenticating user
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            user_credential = {'auth_author': auth_author, "workspace": workspace}
            user_credential_json = json.dumps(user_credential)
            resposne = requests.get(f'{task_url}/board/', data=user_credential_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": 'user authentication failed'})
    
    
class DeleteBoard(APIView):
    def delete(self, request, id=None):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            id = str(id)
            response = requests.delete(f'{task_url}/board/delete/{id}/', headers=headers)
            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
            
           
class ColumnsActions(APIView):
    """ Getting all columns data"""
    def get(self, request):
        boolean = 'false'
        board_slug = request.GET.get('board_slug')
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            column_data = {'board_slug': board_slug, 'auth_author': auth_author}
            column_data_json = json.dumps(column_data)
            resposne = requests.get(f'{task_url}/board/columns/', data=column_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
    def post(self, request):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            column_data_json = json.dumps(request.data)
            resposne = requests.post(f'{task_url}/board/columns/', data=column_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
        
    def patch(self, request):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            column_data_json = json.dumps(request.data)
            resposne = requests.patch(f'{task_url}/board/columns/', data=column_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})

        
        
class CardAction(APIView):
    # Given details, creating card
    def post(self, request):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            card_data_json = json.dumps(request.data)
            resposne = requests.post(f'{task_url}/card/', data=card_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
        
    #  Getting all cards data
    def get(self, request):
        boolean = 'false'
        board_slug = request.GET.get('board_slug')
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            card_data = {'auth_author': auth_author, 'board_slug': board_slug}
            card_data_json = json.dumps(card_data)
            resposne = requests.get(f'{task_url}/card/', data=card_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
        
    # Updating card columns data based on given data
    def patch(self, request):
        boolean = 'false'
        card_id = request.data.get('cardId')
        column_id = request.data.get('columnId')
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            card_column_update_data = {'auth_author': auth_author, 'column_id':column_id, 'card_id':card_id}
            card_column_update_data_json = json.dumps(card_column_update_data)
            resposne = requests.patch(f'{task_url}/card/', data=card_column_update_data_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
      
    
class CardEditUpdate(APIView):
    def patch(self, request):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            card_edit_update = json.dumps(request.data)
            resposne = requests.patch(f'{task_url}/card/card-update/', data=card_edit_update, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
    
    
    
    
      
class CardDeleteion(APIView):
    """Given card id, deleting it"""
    def delete(self, request, id=None):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            data = {'auth_author': auth_author}
            data_json = json.dumps(data)
            id = int(id)
            response = requests.delete(f'{task_url}/card/delete/{id}/', data=data_json, headers=headers)
            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
        
   
   
class AddAssignee(APIView):
    def post(self, request):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            data_json = json.dumps(request.data)
            response = requests.post(f'{task_url}/card/assignee/invite/', data=data_json, headers=headers)
            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
   
               
class AssigneeDeleteion(APIView):
    """Deleteing assignee data based on given details"""
    def delete(self, request, id=None):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            data = {'auth_author': auth_author}
            data_json = json.dumps(data)
            id = int(id)
            response = requests.delete(f'{task_url}/card/assignee/{id}/', data=data_json, headers=headers)
            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
        

        
class CommentAction(APIView):
    def post(self, request, id=None):
        boolean = 'false'
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            comment_credential_json = json.dumps(request.data)
            try:
                id=str(id)
                response = requests.post(f'{task_url}/card/comment/{id}/', data=comment_credential_json, headers=headers)
                response.raise_for_status()  # Raise an error for 4xx and 5xx status codes
                data = response.json()
                return Response(data, status=status.HTTP_200_OK)
            except ConnectionError as e:
                return Response({"error": 'Failed to connect to the backend server'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except requests.exceptions.RequestException as e:
                # Handle other request exceptions
                return Response({"error": 'An error occurred during the request'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   


class GetComments(APIView):
    def get(self, request):
        boolean = 'false'
        card_id = request.GET.get('cardId')
        auth_author = request.headers.get('authorization')
        
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            data = {'card_id': card_id}
            get_comment_specific_card_json = json.dumps(data)
            try:
                response = requests.get(f'{task_url}/card/comment/', data=get_comment_specific_card_json, headers=headers)
                response.raise_for_status()  # Raise an error for 4xx and 5xx status codes
                data = response.json()
                return Response(data, status=status.HTTP_200_OK)
            except ConnectionError as e:
                # Log the connection error
                print(f"Connection Error: {e}")
                return Response({"error": 'Failed to connect to the backend server'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except requests.exceptions.RequestException as e:
                # Handle other request exceptions
                print(f"Request Exception: {e}")
                return Response({"error": 'An error occurred during the request'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   

class CreateMeeting(APIView):
    def post(self, request):
        boolean = 'false'
        authorization = request.headers.get('authorization')
        
        data = {'auth_author': authorization, 'manager': 'confirm'}
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(data, success_callback)
        
        if boolean == 'true':
            headers = {'Content-Type': 'application/json'}
            data_json = json.dumps(request.data)
            response = requests.post(f'{task_url}/meeting/create-meeting/', data=data_json, headers=headers)
            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})
 
 
       
class GetMeeting(APIView):
    def get(self, request):
        boolean = 'false'
        workspace = request.GET.get('workspace')
        auth_author = request.headers.get('authorization')
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(auth_author, success_callback)
       
        if boolean == 'true':
            headers= {
                'Authorization': auth_author,
                'Content-Type': 'application/json',
            }
            meeting_credential = {"workspace": workspace}
            meeting_credential_json = json.dumps(meeting_credential)
            resposne = requests.get(f'{task_url}/meeting/', data=meeting_credential_json, headers=headers)
            data = resposne.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": 'user authentication failed'})


class DeleteMeeting(APIView):
    def delete(self, request, id=None):
        boolean = 'false'
        authorization = request.headers.get('authorization')
        
        data = {'auth_author': authorization, 'manager': 'confirm'}
        def success_callback(returned_value):
            nonlocal boolean
            boolean = returned_value
            
        authenticate_user(data, success_callback)
        
        if boolean == 'true':
            headers= {
                'Authorization': authorization,
                'Content-Type': 'application/json',
            }
            id = str(id)
            response = requests.delete(f'{task_url}/meeting/delete/{id}/', headers=headers)

            data = response.json()
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User Authentication Failed"})