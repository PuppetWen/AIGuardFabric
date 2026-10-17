"""Run normally or through the startup command; no SDK imports/decorators."""
import asyncio
import sys
from .worker import echo, asynchronous, values, async_values


def main():
    if sys.argv[1:] != ["--example-argument"]:
        raise SystemExit(9)
    assert echo("private-input") == "private-input"
    assert asyncio.run(asynchronous("private-reply")) == "private-reply"
    stream = values()
    assert next(stream) == 1
    stream.close()

    async def consume():
        stream = async_values()
        assert await stream.__anext__() == 1
        await stream.aclose()

    asyncio.run(consume())
    print("business completed")


if __name__ == "__main__":
    main()
