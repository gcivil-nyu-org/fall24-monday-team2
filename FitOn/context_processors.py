from .dynamodb import get_user


def user_context(request):
    if request.session.get("user_id"):
        user = get_user(request.session["user_id"])
        return {
            "is_admin": user.get("is_admin", False),
            "is_fitness_trainer": user.get("is_fitness_trainer", False),
        }
    return {"is_admin": False, "is_fitness_trainer": False}
