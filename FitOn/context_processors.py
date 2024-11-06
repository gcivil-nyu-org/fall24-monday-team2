from .dynamodb import get_user_by_username


def user_context(request):
    if request.session.get("username"):
        user = get_user_by_username(request.session["username"])
        return {"is_admin": user.get("is_admin", False)}
    return {"is_admin": False}
