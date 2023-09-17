from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, emit
import logging
from dotenv import load_dotenv, find_dotenv
from flask_cors import CORS
import os
import jwt
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from bson.json_util import dumps
import json
import random
import hashlib


load_dotenv(find_dotenv())

db_uri = os.environ.get("DB_URI")
jwt_secret = os.environ.get("JWT_SECRET")

app = Flask(__name__)
CORS(app)
app.config["MONGO_URI"] = db_uri
app.config["JWT_SECRET"] = jwt_secret

mongo = PyMongo(app)
## disabling the default logger
app.logger.disabled = True
werkzeug_logger = logging.getLogger("werkzeug")
werkzeug_logger.disabled = True


socketio = SocketIO(app, cors_allowed_origins="*")


def generateAvatarLink():
    random_number = str(random.random())

    sha256_hash = hashlib.sha256(random_number.encode()).hexdigest()

    result = sha256_hash[:20]

    return "https://api.multiavatar.com/" + result + ".png"


def generateConvName(id1, id2):
    arr = [id1, id2]
    arr.sort()
    return arr[0] + "/" + arr[1]


def addNewConv(
    members=[],
    messages=[],
    convName="",
):
    for i in range(len(members)):
        members[i] = ObjectId(members[i])

    res = mongo.db.conversations.insert_one(
        {"convName": convName, "messages": messages, "members": members}
    )


def saveMessage(message, convName):
    try:
        updates = {"$addToSet": {"messages": message}}
        queryResult = mongo.db.conversations.update_one({"convName": convName}, updates)
        if queryResult.modified_count == 0:
            addNewConv(
                [message["senderId"], message["receiver"]],
                [message],
                convName,
            )
            # print("added new one")
            #
            # pass
            print("no conversation was updated")
    except Exception as e:
        print(e)
        # create a new conv
        addNewConv(
            [message["senderId"], message["receiver"]],
            [message],
            f"{message['senderId']}/{message['receiver']}",
        )
        print("added new one")
        print("err while updating")
        pass

    return ""


def formatConversations(data, reqSender):
    responseData = []

    for converstation in data:
        convName = converstation["convName"]
        convMembers = convName.split("/")
        messagesReceiverId = ""
        for id in convMembers:
            if id != reqSender:
                messagesReceiverId = id
                break
        reciverData = dict(
            mongo.db.users.find_one({"_id": ObjectId(messagesReceiverId)})
        )
        convMsgs = converstation["messages"]
        lastMessage = convMsgs[len(convMsgs) - 1]

        lastMessageSender = lastMessage["senderId"]

        userImg = reciverData["userImg"]
        userName = reciverData["userName"]
        userId = messagesReceiverId
        conv = {
            "isSelected": False,
            "lastMessage": lastMessage["text"],
            "lastMessageSender": lastMessageSender,
            "userImg": userImg,
            "userName": userName,
            "userId": userId,
        }
        responseData.append(conv)
    return responseData


def parse_json(data):
    return json.loads(dumps(data))


############################ Socketio Routes ########################
@socketio.on("message")
def message(data):
    senderName = data["senderName"]
    senderId = data["senderId"]
    userMessage = data["text"]
    receiver = data["receiver"]
    messageId = data["messageId"]
    if receiver:
        join_room(receiver)

    print(f"{senderName} sending {userMessage} to {receiver} ...")

    if receiver:
        message = {
            "senderName": senderName,
            "senderId": senderId,
            "messageId": messageId,
            "text": userMessage,
            "receiver": receiver,
        }

        print(f"{senderName} sent {userMessage} to {receiver} !")
        saveMessage(message, generateConvName(senderId, receiver))

        emit("chat-message", message, to=receiver)


@socketio.on("join-room")
def on_join_room(data):
    if data:
        roomId = data["roomId"]
        userName = data["userName"]
        join_room(roomId)


######################### HTTP Routes #####################


def isUsedName(userName):
    user = mongo.db.users.find_one({"userName": userName})
    if user:
        return True
    else:
        return False


@app.get("/")
def home():
    return "hello world"


@app.post("/signup")
def signUp():
    try:
        userName = request.json["userName"]
        password = request.json["password"]
        userImg = generateAvatarLink()
        print(isUsedName(userName))
        if not isUsedName(userName):
            userID = mongo.db.users.insert_one(
                {
                    "userName": userName,
                    "userImg": userImg,
                    "password": password,
                }
            ).inserted_id
            payload = {"userId": str(userID), "userName": userName, "userImg": userImg}
            jwtToken = jwt.encode(payload, jwt_secret)
        else:
            return {"message": "user Exist", "success": False}, 400

    except Exception as e:
        print(e)
        return {
            "message": "server problem",
            "success": False,
        }, 400

    return {
        "success": True,
        "token": jwtToken,
        "userName": userName,
        "id": str(userID),
    }, 201


@app.post("/signin")
def signIn():
    try:
        userName = request.json["userName"]
        password = request.json["password"]
        user = mongo.db.users.find_one({"userName": userName, "password": password})
    except:
        return {"message": "unvalid request", "success": False}, 400

    if user:
        payload = {
            "userId": str(user["_id"]),
            "userName": userName,
            "userImg": str(user["userImg"]),
        }
        jwtToken = jwt.encode(payload, jwt_secret)
        return {
            "success": True,
            "token": jwtToken,
            "userName": userName,
            "userId": str(user["_id"]),
        }, 200
    else:
        return {"message": "user was not found", "success": False}, 404


@app.get("/userData/<token>")
def getUserData(token):
    try:
        return jwt.decode(token, jwt_secret, ["HS256"]), 200
    except:
        return {"message": "wrong token", "success": False}, 401


@app.get("/getUserConversations/<token>")
def getUserConversations(token):
    try:
        userData = jwt.decode(token, jwt_secret, ["HS256"])
        userId = userData["userId"]
        res = mongo.db.conversations.find({"convName": {"$regex": userId}})
        response = formatConversations(res, userId)
        return {"conversations": response, "success": True}, 200
    except Exception as e:
        print(e)
        return {"message": str(e), "success": False}, 400


## this endpoint will get two users id and will return a conversation object
@app.post("/conversationMessages")
def conversationMessages():
    try:
        senderId = request.json["senderId"]
        receiverId = request.json["receiverId"]
        convName = generateConvName(senderId, receiverId)
        res = mongo.db.conversations.find_one({"convName": convName})
        messages = dict(res)["messages"]
        return {"messages": messages, "success": True}, 200
    except Exception as e:
        print(e)
        return {"message": str(e), "success": False}, 400


@app.get("/getUser/<id>")
def getUserById(id):
    try:
        _userId = ObjectId(id)
        res = mongo.db.users.find_one({"_id": _userId})
        if res:
            user = parse_json(res)

            return {
                "userName": user["userName"],
                "userId": user["_id"]["$oid"],
                "userImg": user["userImg"],
            }
        else:
            return {"message": "user was not found", "success": False}, 404

    except Exception as e:
        return {"message": str(e), "success": False}, 500


if __name__ == "__main__":
    app.logger.disabled = True

    socketio.run(app=app, allow_unsafe_werkzeug=True, debug=True, port=3000)
