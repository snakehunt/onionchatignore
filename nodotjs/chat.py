import json
import time
import uuid

# REDIS KEYS
ROOMS = 'rooms'
USERS = 'users'
IGNORED = 'ignored'
MESSAGES = 'messages'
IP = 'ip'
TIMESTAMP = 'timestamp'
SECRET= 'secret'

# JSON KEYS
ID = 'id'
USER = 'user'
NAME = 'name'
MESSAGE = 'message'
TIME = 'time'
LENGTH = 'length'

def path(key, *path):
    """
    Generate a path for redis.
    """
    return ':'.join([key] + list(path))

def validate(r, user, secret):
    """
    Validate whether a user's secret is right.
    """
    if r.hget(path(USERS, user), SECRET) == secret:
        return True
    else:
        return False

def touch(r, user, ttl, room=None):
    """
    Indicate that a user is active, optionally in a room.
    """
    r.expire(path(USERS, user), ttl)
    if room:
        # If the room is new, send out a notification
        if r.sadd(path(ROOMS), room) == 1:
            _create_room(r, room)
        r.expire(path(ROOMS, room), ttl)

        # If the user is new, send out a notification
        if r.sadd(path(ROOMS, room, USERS), user) == 1:
            _join_room(r, room, user)
        r.expire(path(ROOMS, room, USERS, user), ttl)

def register(r, user, ip=None): # todo IP
    """
    Register a user.

    Returns a secret for the user if they can register, or None otherwise.
    """
    if r.exists(path(USERS, user)):
        return None
    else:
        secret = str(uuid.uuid4())
        _register_user(r, user, ip, secret)
        return secret
        
def ignore(r, room, user, ignored_user, ignored_user_ip):
    """
    Ignore a user
    
    """
    if r.exists(path(USERS, user)) and r.exists(path(USERS, ignored_user)) and ignored_user_ip is not None:
        return _ignore_user(r, room, user, ignored_user, ignored_user_ip)
    else:
        return False
        
def unignore(r, room, user, ignored_user):
    """
    Unignore a user
    
    """

    p = path(IGNORED, user, ignored_user)
    if r.exists(p):   
        return _unignore_user(r, room,  user, ignored_user)
    else:
        return False
        
def message(r, room, user, message):
    """
    Broadcast chat message to all users. Garbage in, garbage out --
    make sure to protect against XSS outside of this.

    User 'None' is interpreted as a system message.

    Returns True if the message was submitted, False otherwise.
    """
    if (user is None) or r.exists(path(ROOMS, room, USERS, user)):
        p = path(ROOMS, room, MESSAGES)
        r.rpush(p, json.dumps({
            USER:    user,
            MESSAGE: message,
            TIME:    time.strftime('%X') 
        }))
        r.publish(p, room)
        return True
    else:
        return False

def rooms(r, id=None):
    """
    Returns a new ID and an array of rooms when the number of rooms changes.
    """
    # Block waiting for something to change
    p = path(ROOMS)
    if id == r.scard(p):
        pubsub = r.pubsub()
        pubsub.subscribe(p)
        pubsub.listen().next()

    rooms = [{ NAME: room, USERS: r.scard(path(ROOMS, room, USERS)), LENGTH: r.llen(path(ROOMS, room, MESSAGES))} for room in r.smembers(p)]
    
    # It's possible for the listener to break us out without changing ID
    return r.scard(p), rooms



def users(r, room, id=None):
    """
    This returns a new ID and an array of users when the ID changes.
    """
    # Block waiting for something to change
    p = path(ROOMS, room, USERS)
    if id == r.scard(p):
        pubsub = r.pubsub()
        pubsub.subscribe(p)
        pubsub.listen().next()
    return r.scard(p), [{ NAME: name } for name in r.smembers(p)]
    
def messages(r, room, id=None, user=None, limit=255):
    """
    Returns a new ID and an array of messages when a new message occurs.

    Max of limit messages are returned.
    """
    # Block waiting for an update to generate something newer
    p = path(ROOMS, room, MESSAGES)
    if id == r.llen(p):
        pubsub = r.pubsub()
        pubsub.subscribe(p)
        pubsub.listen().next()
    # Components are already in JSON
    # Only print message if user isn't ignored
    json_data = []
    for j in r.lrange(p, -limit, -1):
        json_datum = json.loads(j)
        print '================='
        print  json_datum
        print '-================='
        if user is not None and json_datum['user'] is not None: #logged in
            if not _is_ignored_by(r, user, json_datum['user']):
                json_data.append(json_datum)
        else: #not logged in
           json_data.append(json_datum) 
    return r.llen(p), json_data

def flush(r):
    """
    Chuck out expired users and rooms. This should be run at approximately
    the same interval as the timeout.
    """
    users = r.smembers(path(USERS))
    for user in users:
        if not r.exists(path(USERS, user)):
            _kill_user(r, user)

    rooms = r.smembers(path(ROOMS))
    for room in rooms:
        for user in r.smembers(path(ROOMS, room, USERS)):
            if not r.exists(path(ROOMS, room, USERS, user)):
                _leave_room(r, room, user)

def _create_room(r, room):
    r.hmset(path(ROOMS, room), { TIMESTAMP: time.time() } )
    r.publish(path(ROOMS), room)

def _destroy_room(r, room):
    p = path(ROOMS)
    r.srem(p, room)
    r.publish(p, room)

def _join_room(r, room, user):
    r.hmset(path(ROOMS, room, USERS, user), { TIMESTAMP: time.time() })
    r.publish(path(ROOMS, room, USERS), user)
    message(r, room, None, '%s has joined the room.' % user)

def _leave_room(r, room, user):
    p = path(ROOMS, room, USERS)
    r.srem(p, user)
    r.publish(p, user)
    message(r, room, None, '%s has left the room.' % user)

def _register_user(r, user, ip, secret):
    r.hmset(path(USERS, user), {IP: ip,
                                TIMESTAMP: time.time(),
                                SECRET: secret})
    p = path(USERS)
    r.sadd(p, user)
    r.publish(p, user)

def _kill_user(r, user):
    p = path(USERS)
    r.srem(p, user)
    r.publish(p, user)

def _ignore_user(r, room, user, ignored_user, ignored_user_ip):
    r.sadd(IGNORED, user)
    p = path(IGNORED, user, ignored_user)
    ret = r.set(p, ignored_user_ip)
    if ret:
            message(r, room, None, '%s has ignored %s.' % (user, ignored_user))
            return True
    return False

def _unignore_user(r, room, user, ignored_user):
    p = path(IGNORED, user, ignored_user)
    ret = r.delete(p)
    if ret:
        message(r, room, None, '%s has unignored %s.' % (user, ignored_user))
        return True
    return False
    
def _is_ignored_by(r, user, ignored_user):
    """
    This returns True if user is ignoring ignored_user
    """
    p = path(IGNORED, user, ignored_user)
    return  r.exists(p)

    