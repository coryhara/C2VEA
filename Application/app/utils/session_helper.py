from flask import session

def current_user():
    if "user_id" not in session:
        return None
    return {
        "id": session.get("user_id"),
        "name": session.get("user_name"),
        "nickname": session.get("nickname"),
    }