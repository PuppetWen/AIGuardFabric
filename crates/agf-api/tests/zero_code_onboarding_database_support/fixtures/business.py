import os

ERROR = ValueError("owned original error")


def mark(name):
    with open(os.environ["AGF_BUSINESS_COUNTER"], "a", encoding="utf-8") as stream:
        stream.write(name + "\n")


def sync(value):
    mark("sync")
    return value


async def asynchronous(value):
    mark("async")
    return value


def fail():
    mark("fail")
    raise ERROR


async def root():
    mark("root")
    private = {"private": "business-secret-13800138000"}
    first = sync(private) is private
    second = await asynchronous(private) is private
    same_error = False
    try:
        fail()
    except ValueError as caught:
        same_error = caught is ERROR
    assert first and second and same_error
    return {"ok": True, "syncIdentity": first, "asyncIdentity": second, "errorIdentity": same_error}
