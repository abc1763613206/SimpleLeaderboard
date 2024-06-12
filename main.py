import redis
import flask
import hmac
import json
import logging
import os
import re
import datetime
import uuid
import traceback

from CRED import *

redisConn = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD)

import hmac
def hmac_md5(key, s):
    return hmac.new(key.encode('utf-8'), s.encode('utf-8'), 'MD5').hexdigest()

def score_verify(score,time,sign):
    base = str(score) + "VERIFY" +str(time)
    return hmac_md5(HMAC_KEY,base) == sign

def normal_verify(data,sign):
    base = json.dumps(data)
    return hmac_md5(HMAC_KEY,base) == sign

def check_uuid(uuid):
    return re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",uuid)

app = flask.Flask(__name__)


def make_response(data, status=200):
    return flask.Response(json.dumps(data), content_type='application/json', status=status)


@app.route('/update', methods=['POST'])
def update():
    data = flask.request.get_json()
    if not data:
        return make_response(
            {
                "status": 400,
                "error": "Invalid request"
            },400
        )
    try:
        name = data['name']
        uuid = data['uuid']
        if not check_uuid(uuid):
            return make_response(
                {
                    "status": 403,
                    "error": "Invalid UUID"
                },403
            )
        history = data['history']
        highest_score = -1
        highest_time = -1
        for i in history: # verify the sign
            if not score_verify(i['score'],i['time'],i['verification']):
                return make_response(
                    {
                        "status": 403,
                        "error": "Invalid verification! Do not cheat!"
                    },403
                )
            else:
                if int(i['score']) > highest_score:
                    highest_score = int(i['score'])
                    highest_time = int(i['time'])
        if not redisConn.hexists("user",uuid):
            redisConn.hset("user",uuid,name)
        else:
            if redisConn.hget("user",uuid).decode() != name:
                return make_response(
                    {
                        "status": 403,
                        "error": "Invalid name"
                    },403
                )
        for i in history: # 统计生涯总分数
            if not redisConn.hexists(uuid+"_history",i['time']):
                redisConn.hset(uuid+"_history",i['time'],int(i['score']))
                redisConn.zincrby("total_score",int(i['score']),uuid)
        if highest_score > -1:
            if redisConn.hexists(uuid+"_highest","score"):
                if int(redisConn.hget(uuid+"_highest","score")) < highest_score:
                    redisConn.hset(uuid+"_highest","score",highest_score)
                    redisConn.hset(uuid+"_highest","time",highest_time)
                    redisConn.zadd("leaderboard",{uuid: highest_score})
            else:
                redisConn.hset(uuid+"_highest","score",highest_score)
                redisConn.hset(uuid+"_highest","time",highest_time)
                redisConn.zadd("leaderboard",{uuid: highest_score})
        return make_response(
            {
                "status": 200,
                "message": "Update success"
            }
        )
    except Exception as e:
        traceback.print_exc()
        logging.error(e)
        logging.debug(data)
        return make_response(
            {
                "status": 400,
                "error": "Invalid request"
            },400
        )
    

@app.route('/change_name', methods=['POST'])
def change_name():
    data = flask.request.get_json()
    if not data:
        return make_response(
            {
                "status": 400,
                "error": "Invalid request"
            },400
        )
    try:
        name = data['name']
        uuid = data['uuid']
        verification = data['verification']
        if not check_uuid(uuid):
            return make_response(
                {
                    "status": 403,
                    "error": "Invalid UUID"
                },403
            )
        if not redisConn.hexists("user",uuid):
            return make_response(
                {
                    "status": 404,
                    "error": "User not found"
                },404
            )
        if not normal_verify(data,verification):
            return make_response(
                {
                    "status": 403,
                    "error": "Invalid verification"
                },403
            )
        redisConn.hset("user",uuid,name)
        return make_response(
            {
                "status": 200,
                "message": "Change name success"
            }
        )
    except Exception as e:
        logging.error(e)
        logging.debug(data)
        return make_response(
            {
                "status": 400,
                "error": "Invalid request"
            },400
        )

@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    data = redisConn.zrevrange("leaderboard",0,99,withscores=True)
    res = []
    try:
        for i in data:
            nm = redisConn.hget("user",i[0].decode()).decode()
            if "[BANNED_BY_ADMIN]" in nm:
                nm = "该用户已被封禁"
            res.append({
                "uuid": i[0].decode(),
                "name": nm,
                "time": str(datetime.datetime.fromtimestamp(int(redisConn.hget(i[0].decode()+"_highest","time"))).strftime("%Y-%m-%d %H:%M:%S")),
                "score": int(i[1])
            })
        return make_response(
            {
                "status": 200,
                "data": res
            }
        )
    except Exception as e:
        logging.error(e)
        return make_response(
            {
                "status": 500,
                "error": "Internal Server Error"
            },500
        )

@app.route('/history', methods=['GET'])
def history():
    uuid = flask.request.args.get("uuid")
    if not check_uuid(uuid):
        return make_response(
            {
                "status": 403,
                "error": "Invalid UUID"
            },403
        )
    data = redisConn.hgetall(uuid+"_history")
    res = []
    try:
        for i in data:
            res.append({
                "time": int(i.decode()),
                "score": int(data[i].decode())
            })
        res.sort(key=lambda x:x['time'])
        return make_response(
            {
                "status": 200,
                "data": res
            }
        )
    except Exception as e:
        logging.error(e)
        return make_response(
            {
                "status": 500,
                "error": "Internal Server Error"
            },500
        )

@app.route('/total', methods=['GET'])
def total():
    data = redisConn.zrevrange("total_score",0,99,withscores=True)
    res = []
    try:
        for i in data:
            nm = redisConn.hget("user",i[0].decode()).decode()
            if "[BANNED_BY_ADMIN]" in nm:
                nm = "该用户已被封禁"
            res.append({
                "uuid": i[0].decode(),
                "name": nm,
                "score": int(i[1])
            })
        return make_response(
            {
                "status": 200,
                "data": res
            }
        )
    except Exception as e:
        logging.error(e)
        return make_response(
            {
                "status": 500,
                "error": "Internal Server Error"
            },500
        )
    
@app.route('/user', methods=['GET'])
def user():
    uuid = flask.request.args.get("uuid")
    if not check_uuid(uuid):
        return make_response(
            {
                "status": 403,
                "error": "Invalid UUID"
            },403
        )
    name = redisConn.hget("user",uuid)
    if not name:
        return make_response(
            {
                "status": 404,
                "error": "User not found"
            },404
        )
    highest = redisConn.hget(uuid+"_highest","score")
    highest_time = redisConn.hget(uuid+"_highest","time")
    total = redisConn.zscore("total_score",uuid)
    return make_response(
        {
            "status": 200,
            "uuid": uuid,
            "name": name.decode(),
            "highest": {
                "score": int(highest) if highest else None,
                "time": int(highest_time) if highest_time else None
            },
            "total": int(total) if total else 0
        }
    )

@app.route('/', methods=['GET'])
def index():
    return make_response(
        {
            "status": 200,
            "message": "Welcome to the game server!"
        }
    )

@app.route('/debug/uuidgen', methods=['GET'])
def uuidgen():
    return make_response(
        {
            "status": 200,
            "uuid": str(uuid.uuid4())
        }
    )

@app.route('/debug/hmac', methods=['POST'])
def debug_hmac():
    data = flask.request.get_json()
    try:
        base = data["base"]
        key = data["key"]
        return make_response(
            {
                "status": 200,
                "result": hmac_md5(key,base)
            }
        )
    except Exception as e:
        logging.error(e)
        return make_response(
            {
                "status": 400,
                "error": "Invalid request"
            },400
        )



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)