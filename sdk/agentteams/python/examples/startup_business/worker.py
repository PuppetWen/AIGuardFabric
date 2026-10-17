"""Example business callables. The startup configuration, not this file, adds telemetry."""
import asyncio

calls = []


def echo(value):
    calls.append("echo")
    return value


def fail(error):
    calls.append("fail")
    raise error


def invoke(value):
    calls.append("invoke")
    return echo(value)


def mcp_reply(value):
    calls.append("mcp")
    return value


async def asynchronous(value):
    calls.append("async")
    await asyncio.sleep(0)
    return value


async def waiting(ready):
    calls.append("waiting")
    ready.set()
    await asyncio.Event().wait()


def values():
    calls.append("values")
    received = yield 1
    try:
        yield received
    except LookupError as error:
        yield error
    return 7


async def async_values():
    calls.append("async_values")
    received = yield 1
    try:
        yield received
    except LookupError as error:
        yield error


class WorkerClient:
    def __init__(self, value):
        self.value = value

    def run(self):
        calls.append("method")
        return self.value

    @staticmethod
    def static_run(value):
        calls.append("static")
        return value

    @classmethod
    def class_run(cls, value):
        calls.append("class")
        return cls(value)

    @property
    def unsafe_property(self):
        raise AssertionError("A property must never be evaluated by injection")


from asyncio import sleep as imported_alias
