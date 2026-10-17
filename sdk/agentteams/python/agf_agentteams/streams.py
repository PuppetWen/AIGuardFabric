"""Lazy generator forwarding: no draining, buffering, retrying or swallowed errors."""
import time
from . import context
from .events import status


class Stream:
    def __init__(self, iterator, span, argument_count, keyword_count):
        self.iterator, self.span = iterator, span
        self.counts = argument_count, keyword_count
        self.started = False

    def __iter__(self):
        return self

    def __next__(self):
        return self._step(self.iterator.__next__)

    def send(self, value):
        return self._step(self.iterator.send, value)

    def throw(self, *arguments):
        return self._step(self.iterator.throw, *arguments)

    def _step(self, function, *arguments):
        was_started = self.started
        if not self.started and self.iterator.gi_frame is not None:
            self.started = True
            self.span.started = time.monotonic()
        token = context.current.set(self.span.context)
        try:
            return function(*arguments)
        except StopIteration:
            if self.started:
                self.span.finish("success", *self.counts)
            raise
        except BaseException as error:
            if self.started and self.iterator.gi_frame is None:
                self.span.finish(status(error), *self.counts)
            elif not was_started:
                self.started = False  # Invalid initial send did not enter the generator.
            raise
        finally:
            context.current.reset(token)

    def close(self):
        token = context.current.set(self.span.context)
        try:
            return self.iterator.close()
        except BaseException as error:
            if self.started and self.iterator.gi_frame is None:
                self.span.finish(status(error), *self.counts)
            raise
        finally:
            if self.started and self.iterator.gi_frame is None:
                self.span.finish("unknown", *self.counts)
            context.current.reset(token)


class AsyncStream:
    def __init__(self, iterator, span, argument_count, keyword_count):
        self.iterator, self.span = iterator, span
        self.counts = argument_count, keyword_count
        self.started = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self._step(self.iterator.__anext__)

    async def asend(self, value):
        return await self._step(self.iterator.asend, value)

    async def athrow(self, *arguments):
        return await self._step(self.iterator.athrow, *arguments)

    async def _step(self, function, *arguments):
        was_started = self.started
        if not self.started and self.iterator.ag_frame is not None:
            self.started = True
            self.span.started = time.monotonic()
        token = context.current.set(self.span.context)
        try:
            return await function(*arguments)
        except StopAsyncIteration:
            if self.started:
                self.span.finish("success", *self.counts)
            raise
        except BaseException as error:
            if self.started and self.iterator.ag_frame is None:
                self.span.finish(status(error), *self.counts)
            elif not was_started:
                self.started = False
            raise
        finally:
            context.current.reset(token)

    async def aclose(self):
        token = context.current.set(self.span.context)
        try:
            return await self.iterator.aclose()
        except BaseException as error:
            if self.started and self.iterator.ag_frame is None:
                self.span.finish(status(error), *self.counts)
            raise
        finally:
            if self.started and self.iterator.ag_frame is None:
                self.span.finish("unknown", *self.counts)
            context.current.reset(token)
