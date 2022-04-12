from cProfile import label
from builtins import print
# from traceback import print_tb
from kivy.clock import Clock
import kivymd as MD

from kivymd.app import MDApp
from kivymd.theming import ThemableBehavior, ThemeManager
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton
from kivymd.uix.tab import MDTabsBase
from kivy.uix.label import Label
from kivymd.uix.list import ImageLeftWidget, IconRightWidget, ImageRightWidget
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.toast import toast
from kivymd.uix.button import MDFloatingActionButtonSpeedDial
from kivymd.uix.list import TwoLineAvatarListItem

import kivy
from kivy.lang import Builder
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.floatlayout import FloatLayout
from kivy.network.urlrequest import UrlRequest
from kivy.utils import platform
#scrManager = ObjectProperty(None)
from kivy.storage.dictstore import DictStore


from kivy.core.window import Window
Window.softinput_mode = "pan"
#Window.size = (475, 850)   
#
from plyer import filechooser

import base64

import json


from functools import partial

import requests
import threading
from time import sleep
import random


import rsa
import pickle
import sqlite3
from sqlite3 import Error as sqError

sm = ScreenManager()

URL = "ServerNameHere/CHAT/"


# Defines WelcomeScreen instance as a screen widget.
class WelcomeScreen(Screen): 
    pass

# Defines LoginScreen instance as a screen widget.
class LoginScreen(Screen):  

    def CheckLoginData(self):
        username = self.ids.usernameField.text
        password = self.ids.passwordField.text

        #Create request
        data = {}
        data["username"] = username
        data["password"] = password
        headers = {"Content-Type":"application/json"}
        url = URL + "API/Authentication/login.php"
        data = json.dumps(data)

        #Make request to server
        response = requests.post(url, data=data, headers=headers)
        try:
            print(response.json())
            jsonData = response.json()
        except:
            toast("Try again later")
            return 0

        try:
            error = jsonData["error"]
            if error == "invalid password":
                self.ids.passwordField.hint_text = "Invalid Password"
                self.ids.passwordField.current_hint_text_color = [1,0,0,0.7]
                self.DialogError("Invalid Password")

            if error == "login fail":
                self.ids.passwordField.text = ""
                self.ids.usernameField.text = ""
                self.DialogError("Invalid Username and/or Password")

            if error == "empty variables":
                if jsonData["variable missing"] == "username":
                    self.ids.usernameField.text = ""
                    self.DialogError("Invalid Username")
                elif jsonData["variable missing"] == "password":
                    self.ids.passwordField.text = ""
                    self.DialogError("Invalid Password")
            
            if error == "invalid password":
                self.ids.passwordField.text = ""
                self.DialogError("Invalid Password")    
        except:
            print("to many errors")


        CheckUp = False
        try:
            print(jsonData["login"])
            CheckUp = True
        except:
            print("not logged in")
            

        # setup current user details
        try: 
            MainApp.userID = jsonData["id"]
            MainApp.username = username
            MainApp.jwt = jsonData["token"]
            if MainApp.ReturnDataFromDictStore('UserID') != MainApp.userID:

                MainApp.InsertToDictStore("UserPrivate", 'None') 
                MainApp.InsertToDictStore("UserPublic", 'None')

            MainApp.InsertToDictStore("UserID", MainApp.userID) 
            MainApp.InsertToDictStore("UserName", MainApp.username) 
            MainApp.InsertToDictStore("UserJWT", MainApp.jwt) 
        except Exception as err:
            print("error: " + str(err))


        if CheckUp:
            self.Sendkey()
    dialog = None

    def Sendkey(self):
        checker = False    


        Pri = MainApp.ReturnDataFromDictStore('UserPrivate')
        Pub = MainApp.ReturnDataFromDictStore('UserPublic')
        # Check if there are previously stored keys
        if  Pri['name'] =='None' or Pub['name']=='None':
            checker = False
        else:
            checker = True
            


        if checker:
            #Loading Keys from Dict
            MainApp.privateKey = rsa.PrivateKey.load_pkcs1(Pri["name"], format='PEM')
            MainApp.publicKey = rsa.PublicKey.load_pkcs1(Pub["name"], format='PEM')

        else:
            #Create Keys
            (MainApp.publicKey,MainApp.privateKey)=rsa.newkeys(512)#2048/4096

            #Convert Keys to string
            privateStringKey = rsa.PrivateKey.save_pkcs1(MainApp.privateKey, format='PEM')
            publicStringKey = rsa.PublicKey.save_pkcs1(MainApp.publicKey, format='PEM')
            #Store Key into Dict
            MainApp.InsertToDictStore("UserPrivate", privateStringKey) 
            MainApp.InsertToDictStore("UserPublic", publicStringKey) 
            
        
    
        publicStringKey = rsa.PublicKey.save_pkcs1(MainApp.publicKey, format='PEM')
              
        data = {}
        data["key"] = publicStringKey.decode('ascii')   
        data["jwt"] = MainApp.jwt

        headers = {"Content-Type":"application/json"}
        url = URL + "API/Users/setPK.php"
        data = json.dumps(data)
        print("Sending keys ")
        response = requests.post(url, data=data, headers=headers)
        try:
            
            print(response.json())
            jsonData = response.json()
        except KeyError as err:
            print("Try again later" + str(err))
            return 0
        try:
            # print(jsonData["error"])
            error = jsonData["error"]
            if error == "empty variables":
                print("Error: " +error)
            if error == "fail":
                print(error)
        except:
            print("no errors")


        
        try: 
            print(jsonData["success"])
            success = jsonData["success"]

        except:
            toast('Try again in a few seconds')
            print("to many errors")
            #self.Sendkey()
            return 0


        self.manager.current = 'main_screen'
      
        
    def PublicKeyToJson(self, publicKey):
        a = pickle.dumps(publicKey)
        a = base64.b64encode(a)
        a = a.decode('ascii')
        aJson = json.dumps(a)
        return aJson

    def JsonToPublicKey(self, jsonKey):
        a = json.loads(jsonKey)
        a = base64.b64decode(a)
        a = pickle.loads(a)
        return a
                
    def DialogError(self, text, title = "Error" ):
        
        if not self.dialog:
            self.dialog = MDDialog(title= title,
                text=text,
                buttons=[
                    MDFlatButton(
                        text="OK", text_color=ThemeManager().primary_color, on_release=self.close_dialog
                    )
                ],
            )

        self.dialog.open()

    def close_dialog(self, inst):
        self.dialog.dismiss()
    
    
    


class WaitingForLoginResults(Screen):


    def SendDataToServer(self, data):
        pass

    def DisplayLoadingSpiral(self):
        pass

    def StoreStoken(self, token):
        pass



class RegisterScreen(Screen):  # Defines RegisterScreen instance as a screen widget.


    def GetData(self):

        username = self.ids.usernameFieldRegister.text
        password = self.ids.passwordFieldRegister.text
        passwordRepeat = self.ids.passwordRepeatFieldRegister.text

        if password == passwordRepeat:
            MainApp.info = {
                "username": username,
                "password": password,
                "passwordRepeat":passwordRepeat
            }
            return True

        else:
            return False





class RegisterAdditionalScreen(Screen):

                # Get user data
    def GetData(self):

        self.isEmail = self.ids.emailCheckBox.active
        self.email = self.ids.emailField.text
        self.isPhone = self.ids.phoneCheckBox.active
        self.phone = self.ids.phoneNumberField.text
        self.phonePrefix = self.ids.phonePrefixField.text
        self.username = MainApp.info['username']
        self.password = MainApp.info['password']
        self.passwordRepeat= MainApp.info['passwordRepeat']




    def MakeRequest(self):

        self.GetData()
        #print(self.isEmail)
        data = {}
        data["username"] = self.username
        data["password"] = self.password
        data["passwordRepeat"] = self.passwordRepeat
        if self.isEmail:
            data["isEmail"] = 1
            data["email"] = self.email
        else:
            data["isEmail"] = 0
            data["email"] = "NULL"

        if self.isPhone:
            data["isPhone"] = 1
            data["phone"] = self.phone
            data["phonePrefix"] = self.phonePrefix
        else:
            data["isPhone"] = 0
            data["phone"] = "NULL"
            data["phonePrefix"] = "NULL"

        headers = {"Content-Type":"application/json"}
        url = URL + "API/Authentication/register.php"
        data = json.dumps(data)
        response = requests.post(url, data=data, headers=headers)


        try:
            jsonData = response.json()
            print (jsonData)
        except:
            toast("Try again later")

        try:
            error = jsonData["error"]
            # print(error)
            if error == "username taken":
                register = RegisterScreen()

                register.ids.usernameFieldRegister.text = ""
                register.ids.usernameFieldRegister.text = ""
                register.ids.usernameFieldRegister.hint_text = "Username taken"
                register.ids.usernameFieldRegister.current_hint_text_color = [1,0,0,0.7]
                
                self.manager.current = 'register_screen'
                print("U taken")
            elif error == "email taken":
                self.ids.emailField.text = ""
                self.ids.emailField.hint_text = "Email taken"
                self.ids.emailField.current_hint_text_color = [1,0,0,0.7]
                self.manager.current = 'register_additional_screen'
                print("E taken")
                
            elif error == "phone taken":
                self.ids.phoneNumberField.text = ""
                self.ids.phoneNumberField.hint_text = "Phone taken"
                self.ids.phoneNumberField.current_hint_text_color = [1,0,0,0.7]
                self.manager.current = 'register_additional_screen'
                print("P taken")
        except:
            print("no errors")


        #Check if registration is completed and proceed to next screen  
        try:
            print(jsonData["account"])
            self.manager.current = 'login_screen'

        except:
            print("not register")
            self.manager.current = 'register_screen'


        # If the switch is active enable checkboxes for phone and email
    def ChangeInputSwitch(self):
        if self.ids.additionalInfoSwitch.active:
            self.ids.emailCheckBox.disabled = False
            self.ids.phoneCheckBox.disabled = False

        # disable checkboxes for phone and email
        else:
            self.ids.emailCheckBox.disabled = True
            self.ids.phoneCheckBox.disabled = True


    def ChangeInputEmail(self):
        if self.ids.emailCheckBox.active:
            print("")
            self.ids.emailField.disabled = False
        else:
            self.ids.emailField.disabled = True


    def ChangeInputPhone(self):
        if self.ids.phoneCheckBox.active:
            self.ids.phonePrefixField.disabled = False
            self.ids.phoneNumberField.disabled = False
        else:

            self.ids.phonePrefixField.disabled = True
            self.ids.phoneNumberField.disabled = True

class TermsAndConditionsScreen(Screen):  # Defines TermsAndConditions instance as a screen widget.
    # This function makes the continuing button to appear
    # If the checkbox for therms and conditions is checked
    def ChangeCheckBoxState(self):
        print(self.ids.t_mCheck.active)

        if self.ids.t_mCheck.active:
            self.ids.t_mButton.opacity = 50
            self.ids.t_mButton.disabled = False
        else:
            self.ids.t_mButton.disabled = True
            self.ids.t_mButton.opacity = 0



class ForgotPassword(Screen):

    def CheckUsername(self):
        username = self.ids.usernameField.text
        data = {}
        data["username"] = username

        headers = {"Content-Type":"application/json"}


class SettingsScreen(Screen):
    # https://github.com/kivymd/KivyMD/issues/213
    def BackToMain(self):
        self.manager.transition.direction = "left"
        MDApp.get_running_app().root.current = "main_screen"

    pass


class MainScreen(Screen):
    
    def test(self):

        import plyer
        plyer.notification.notify(title='test', message="Notification using plyer")


    def AddNewFriend(self):
        searchFor = self.ids.usernameInput.text
        data = {}
        data["username"] = searchFor
        url = URL+"API/Friends/findFriend.php"

   

    def SearchForUser(self, id):
        data = {}
        data["id"] =id
        headers = {"Content-Type":"application/json"}
        url = URL+ "/API/Users/findUser.php"
        data = json.dumps(data)

        response = requests.post(url, data=data, headers=headers)
        jsonData = response.json()
        #print(jsonData)

        try:
        # print(jsonData["error"])
            error = jsonData["error"]
            if error == "empty variables":
                print(error)
                self.ids.usernameField.hint_text = "empty UserName"
                #self.ids.usernameField.current_hint_text_color = [1,0,0,0.7]
                # self.DialogError("Invalid Password")
        except:
            print("what")

        
    #try:
    # print(jsonData["error"])
        username = jsonData["username"]
        self.id = jsonData["id"]
        
        details = [username, self.id]

        return details 


    def PublicKeyToJson(self, publicKey):
        a = pickle.dumps(publicKey)
        a = base64.b64encode(a)
        a = a.decode('ascii')
        aJson = json.dumps(a)

        return aJson

    def JsonToPublicKey(self, jsonKey):
        a = json.loads(jsonKey)
        a = base64.b64decode(a)
        a = pickle.loads(a)

        return a



    def on_pre_leave(self):
        try:
            self.event.cancel()
        except:
            pass

        #random.randint(1, 3)
    def on_pre_enter(self):
        self.i = 0
        sizes = Window.size
        screenHeight = sizes[1]
        paddingHeight = screenHeight / 12
        self.ids.container.padding = [30, paddingHeight, 30, 0 ]
        self.ids.mainToolbar.height = paddingHeight
        
        #Setup Username in the drawer window
        self.ids.usernameLabel.text=MainApp.username
        self.DisplayAllFriends()
 
    def OpenChat(self, instance ):

        print(instance.secondary_text)
        print(instance.text)
        Chat.fromName = instance.text
        Chat.fromID = instance.secondary_text

        #Make request to get Pub Key of Receiver

        headers = {"Content-Type":"application/json"}
        url = URL + "API/Users/getPubKey.php"
        data = {}
        data["jwt"] = MainApp.jwt
        data["id2"] = Chat.fromID
        data = json.dumps(data)
        response = requests.post(url, data=data, headers=headers)

        try:    
            print(response)

        except:
            return 0

        try: 
            jsonData = response.json()
        except:
            return 0

        try: 
            error = jsonData["error"]
            return 0

        except:
            print("no errors from receiving the PubKey of the receiver")

        try: 
            receiverPubKey = jsonData["pubKey"]
            print(receiverPubKey.encode("ascii"))
            print("Testing the key")
            Chat.fromPubKey = rsa.PublicKey.load_pkcs1(receiverPubKey.encode("ascii"), format='PEM')

        except Exception as err:
            print("error loading the receiver Public Key: " + str(err))

        self.manager.transition.direction = "left"
        self.manager.current = 'chat_screen'

        pass

    def RequestAllFriends(self):

        pass


    def DisplayAllFriends(self):

        headers = {"Content-Type":"application/json"}
        url = URL + "API/Friends/getListOfFriendsThathaveUnreadMessagesFrom.php"
        data = {}
        data["jwt"] = MainApp.jwt
      
        data = json.dumps(data)

        response = requests.post(url, data=data, headers=headers)

        try:    
            print(response)

        except:
            return 0

        try: 
            jsonData = response.json()
        except:
            return 0

        try: 
            error = jsonData["error"]
        except:
            print("no errors from geting new messages")

        try:
            listOfFriends = jsonData["list"]
        except:
            return 0

        try: 
            print("Testing Deletion of friends in current list")
            self.ids.container.clear_widgets()
        except:
            print("failed")

        for friendDetails in listOfFriends:

            item = TwoLineAvatarListItem(text='@'+str(friendDetails[1]), secondary_text=str(friendDetails[0]), on_release = self.OpenChat)               
            
            item.add_widget(ImageLeftWidget(source='src/avatars/cropped-Avatar-Round.png'))
            self.ids.container.add_widget(item)                


class SearchFriend(Screen):


    def on_pre_enter(self):
        sizes = Window.size
        screenHeight = sizes[1]
        paddingHeight = screenHeight / 12
        self.ids.showUserList.padding = [0, paddingHeight, 0, 0 ]
        self.ids.searchFriendToolbar.height = paddingHeight

    def AddNewFriend(self, id, *args):
        print ("This is the ID: "+str(id))

        data = {}
        data["jwt"] = MainApp.jwt
        data["id2"] = id
        

        headers = {"Content-Type":"application/json"}
        url = URL+ "/API/Friends/addNewFriend.php"
        data = json.dumps(data)

        response = requests.post(url, data=data, headers=headers)
        try:
            print ("response:")
            print(response.json())
        except:

            pass


        try: 
            jsonData = response.json()
            error = jsonData["error"]
            if error == "already friends":
                toast("You are already friends")
        except:
            pass

        try:
            jsonData = response.json()
            if jsonData['success'] == 'friendship created':
                toast("User Added to Friends")
                self.manager.transition.direction = "up"
                self.manager.current = 'main_screen'
        except:
            toast("Error try again later.")



        

    def SearchForUser(self):
        self.ids.usernameField.hint_text = "Enter username"
        #self.ids.usernameField.current_hint_text_color = [1,0,0,0.7]
        if not self.ids.usernameField.text:
            self.ids.usernameField.hint_text = "Empty UserName"
            #self.ids.usernameField.current_hint_text_color = [1,0,0,0.7]
            return 0
        
        data = {}
        data["jwt"]=MainApp.jwt
        data["username"] = self.ids.usernameField.text

        headers = {"Content-Type":"application/json"}
        url = URL+ "/API/Users/findUser.php"
        data = json.dumps(data)

        response = requests.post(url, data=data, headers=headers)
        jsonData = response.json()

        try:
            error = jsonData["error"]
            if error == "empty variables":
                print(error)
                self.ids.usernameField.hint_text = "empty UserName"
        except:
            print("what")

        
        self.username = jsonData["username"]
        self.id = jsonData["id"]
        if self.username and self.id: 
            print (self.username)
            print(id)
            #id=id ,         
            fullUsername = '@' + self.username
            item = TwoLineAvatarListItem(text=fullUsername, secondary_text="")
            #https://stackoverflow.com/questions/33586688/kivy-button-binding-function-with-argument
            callback = partial(self.AddNewFriend, self.id)

            item.bind(on_release=callback)

            item.add_widget(ImageLeftWidget(source='src/avatars/cropped-Avatar-Round.png'))
            self.ids.showUserList.add_widget(item)
            return 0


    def AddFriend(self):
        self.close_dialog
    
    def close_dialog(self, inst):
        self.dialog.dismiss()

    # https://github.com/kivymd/KivyMD/issues/213
    def BackToMain(self):
        self.manager.transition.direction = "down"
        MDApp.get_running_app().root.current = "main_screen"
    

class Chat(Screen):
    fromID = 0
    fromName = ""
    Screen.fromID = 0
    Screen.fromPubKey = None

    data = {
        'paperclip': 'File',
        'camera': 'Camera',
        'microphone': 'Voice',
        'compass-outline': 'Location'
    }


    def OpenCamera(self):
        print('Opening the camera')  
        toast('Opening the camera')
    
    def OpenFile(self):
        print('Opening file Manager')
        toast('Opening FileManager')
        Chat.SelectFile(self)

    def OpenVoiceRecorder(self):
        print('Opening Voice Recorder')
        toast('Opening Voice Recorder')

    def SendingLocation(self):
        print('Sendig Location')
        toast('Sending Locartion')



    def SendMessage(self):
        message = self.ids.messageTextField.text
        print("send message:")
        print(message)

        try:
            enMess, enKey = self.EncryptMessage(message)
        except Exception as err:
            print("error: "+ str(err))
            return 0


        if self.SendMessageRequest(Chat.fromID, self.PublicKeyToJson(enMess), self.PublicKeyToJson(enKey)):

            self.DisplayNewMessage(message, 1)
        else:
            print("not good")

        try:
            pass
        except Exception as Err:
            print("error: "+str(Err))



    def PublicKeyToJson(self, publicKey):
        a = pickle.dumps(publicKey)
        a = base64.b64encode(a)
        a = a.decode('ascii')
        aJson = json.dumps(a)
        return aJson

    def JsonToPublicKey(self, jsonKey):
        a = json.loads(jsonKey)
        a = base64.b64decode(a)
        a = pickle.loads(a)
        return a

        
    # from android.runnable import run_on_ui_thread
    # @run_on_ui_thread
    def EncryptMessage(self, message):
        print("x")
        
        #from jnius import cast 
        print("yy")
        from jnius import autoclass
        print("y")
        self.Encrypt = autoclass('Encrypt')
        print("z")
        
        try:
            encryptedMessageAndKey = self.Encrypt.EncryptData(str(message))
        except KeyError as Err:
            print("error: "+ str(Err))

        print("[Message]: " + message)
        print("[Message]: " + encryptedMessageAndKey[0])
        # print(str(type(encryptedMessageAndKey[0])))

        print("[AES Key]: "+encryptedMessageAndKey[1])        

        encryptedMessage = encryptedMessageAndKey[0]
        AesKey = encryptedMessageAndKey[1]

        print("[Encrypting the AES Key]: ")

        encodedAesKey = AesKey.encode()
        # https://www.kite.com/python/answers/how-to-convert-a-string-to-a-byte-array-in-python
        byteAesKey = bytearray(encodedAesKey)
                
        asymAesKey = rsa.encrypt(byteAesKey, Chat.fromPubKey)

        return(encryptedMessage, asymAesKey )


        
    def PublicKeyToJson(self, publicKey):
        a = pickle.dumps(publicKey)
        a = base64.b64encode(a)
        a = a.decode('ascii')
        aJson = json.dumps(a)
        return aJson

    # from android.runnable import run_on_ui_thread
    # @run_on_ui_thread
    def DecryptMessage(self, EnMess, EnAES):
        from jnius import cast 
        from jnius import autoclass
        self.Encrypt = autoclass('Encrypt')

        print(EnMess)
        try:
            decrypted_message = rsa.decrypt(EnAES, MainApp.privateKey)
        except:
            
            self.MessageAcknowledgement([self.mesID])
            return 0
            
        print("[AES decrypted Key]: ")
        print(decrypted_message.decode())


        y = self.Encrypt.DecryptData(EnMess, decrypted_message)


        print("[Message]: "+ y)
        return y

    def GetNewMessages(self, dt=None):
        headers = {"Content-Type":"application/json"}
        url = URL + "API/Messages/getNewMessagesFromFriend.php"
        
        print ("requesting New Messages")
        
        data = {}
        data["jwt"] = MainApp.jwt
        data["fromID"] = Chat.fromID

        data = json.dumps(data)
        response = requests.post(url, data=data, headers=headers)

        try:    
            jsonData = response.json()
            print(jsonData)

        except:
            toast("Try again later")
            return 0

        try: 
            print(jsonData["success"])
            if jsonData["success"] =="no new messages":
                return 0
             
            elif jsonData["success"] =="New Messages":
                pass

        except KeyError as err:
            print("Something happend: "+ str(err))

        self.mesID = 0 
        noOfMess = jsonData["new Messages"]
        print(noOfMess)
        actualMessages = jsonData["m"]
        # print (actualMessages)
        listOfMessages = []
        for message in actualMessages:
            print("Message from: " +str(message['fromID']))
            print("Content: "+message['message'])
            print("Key: "+ message["key"])
            self.mesID = message['id']

            print("Decrypted Message: ")
            decrypted=self.DecryptMessage(self.JsonToPublicKey(message['message']),self.JsonToPublicKey(message['key']))
            print("Decrypted Message: " + str(decrypted) )
            if decrypted == 0:
                listOfMessages.append(message['id'])
            else:

                self.DisplayNewMessage(decrypted, 0)
                listOfMessages.append(message['id'])
        self.MessageAcknowledgement(listOfMessages)
        try:
            pass
        except KeyError as err:
            print("Something happend: "+ str(err))

    def MessageAcknowledgement(self, listOfMessagesReceived):
        headers = {"Content-Type":"application/json"}
        url = URL + "API/Messages/deleteReceivedMessages.php"
        
        print ("requesting New Messages")
        
        data = {}
        data["jwt"] = MainApp.jwt
        data["listOfMessages"] = listOfMessagesReceived
        print("1")
        data = json.dumps(data)
        print("2")

        response = requests.post(url, data=data, headers=headers)
        print("3")
        try:    
            jsonData = response.json()
            print(jsonData)

        except:
            toast("Try again later")
            return 0

        try: 
            print(jsonData["success"])
            return 1
        except:

            return 0   

        pass

    def SendMessageRequest(self,receiver, message, keyM):
        headers = {"Content-Type":"application/json"}
        url = URL + "API/Messages/sendMessage.php"
        
        print ("requesting New Messages")
        
        data = {}
        data["jwt"] = MainApp.jwt
        data["toID"] = receiver
        data["message"] = message
        data["messageKey"] = keyM

        data = json.dumps(data)
        response = requests.post(url, data=data, headers=headers)

        try:    
            jsonData = response.json()
            print(jsonData)

        except:
            toast("Try again later")
            return 0

        try: 
            print(jsonData["success"])
            return 1
        except:

            return 0     
               
        
        pass

    def UpdateReceivedMessages(self):
        print("hello")

        

    def DisplayNewMessage(self, message, receivedOrSend):

        
        orientation = ""
        if receivedOrSend:
            orientation = "right"
            self.ids.messageTextField.text = ""

        else:
            orientation = "left"



        messageLabel = MyChatLable(text=message,halign=orientation)
        self.ids.container.add_widget(messageLabel)


    def on_pre_enter(self):
        sizes = Window.size
        screenHeight = sizes[1]
        paddingHeight = screenHeight / 12
        self.ids.container.padding = [0, paddingHeight, 0, 0 ]
        self.ids.chatToolbar.height = paddingHeight
        screenWidth = sizes[0]
        messageWidth = screenWidth / 10 * 8

        self.ids.chatToolbar.title=""
        self.ids.chatToolbar.title = Chat.fromName

        self.event = Clock.schedule_interval(self.GetNewMessages, 5)#20s=None between request
        try: 
            print("Testing Deletion of friends in current list")
            self.ids.container.clear_widgets()
        except:
            print("failed")
        
        self.GetNewMessages()

    def on_pre_leave(self):

        try:
            self.event.cancel()
        except:
            pass

    def SelectFile(self):
        ##x = "https://www.google.com/maps/@?api=1&map_action=map&center=-33.712206,150.311941"

        #headers = {"Content-Type":"application/json"}
        #url = "https://vesta.uclan.ac.uk/~asavu/CHAT/API/Users/findUser.php"
        #data = json.dumps(data)

        #response = requests.post(x)
        #jsonData = response.json()
        #print(jsonData)


        # filechooser.open_file(on_selection=Chat.handle_selection(self,  **kwargs))
        filechooser.open_file(on_selection=Chat.handle_selection)

        
    def handle_selection(self, selection):
        '''
        Callback function for handling the selection response from Activity.
        '''
        Chat.selection = selection

    def on_selection(self, *a, **k):
        
        '''
        Update TextInput.text after FileChoose.selection is changed
        via FileChoose.handle_selection.
        '''
        print (str(Chat.selection))


        return str(Chat.selection)


    def BackToMain(self):
        self.manager.transition.direction = "right"
        MDApp.get_running_app().root.current = "main_screen"
    

# Create multiple tabs page functionality  
class Tab(FloatLayout, MDTabsBase):
    pass

class MyChatLable(Label):

    pass

class MainApp(MDApp):
    info = {}

    def callback(self, instance):
        print(instance.icon)
        if instance.icon == 'paperclip':
            Chat.OpenFile(self)
            pass
        elif instance.icon == 'camera':
            Chat.OpenCamera(self)

            pass
        elif instance.icon =='microphone':
            Chat.OpenVoiceRecorder(self)
            pass
        elif instance.icon == 'compass-outline':
            Chat.SendingLocation(self)
            pass

    def InsertToDictStore(key, value):
        try:
            store = DictStore(filename="MY_SETTINGS")
            store.put(key, name=value)
           # print(value)
            print("storing data")

        except Exception as err:
            print ("KIVY, 5, error: {}".format(repr(err)))
            toast("Couldn't store data into MY_SETTINGS")
            print("Couldn't store data into MY_SETTINGS")


    def ReturnDataFromDictStore(key):
        try:
            print("returning data")
            store = DictStore(filename="MY_SETTINGS")
            dictionary = store.get(key)
            # print(dictionary)
            return dictionary

        except KeyError as err:
            dictionary = {'name' : 'None'}
           # print(dictionary)
            return dictionary


    def build(self):
        self.theme_cls.theme_style = "Dark"
        #self.root_widget = Builder.load_string(kv)
        self.root_widget = Builder.load_file('mainTest.kv')
        MainApp.username = None
        MainApp.userID = None
        MainApp.privateKey = None
        MainApp.publicKey = None
        MainApp.jwt = None
        MainApp.friends = None
     
        self.DisableScreenShoting()

        return self.root_widget

    def TestNetwork(self):
        try:
            response = requests.get("https://1.1.1.1")
        except:
            pass

    def SetToken(self, token):
        self.token = token

    # this code is inspired form: https://stackoverflow.com/questions/60576356/getwindow-addflagslayoutparams-flag-secure-inside-flutterfragmentactivity-no
    from android.runnable import run_on_ui_thread
    @run_on_ui_thread
    def DisableScreenShoting(self):
        if platform == 'android':
            from jnius import cast 
            from jnius import autoclass

            # get the android activity 
            PythonActivity = autoclass('org.kivy.android.PythonActivity') 
            # set the android activity as the main activity 
            activity = PythonActivity.mActivity
            currentActivity = cast('android.app.Activity', activity)
            # get the window manager object using main activity
            WindowManager = autoclass('android.view.WindowManager$LayoutParams')
            # setting up flag_secure for the window manager  
            currentActivity.getWindow().addFlags(WindowManager.FLAG_SECURE)
            


if __name__ == '__main__':
    MainApp().run()


