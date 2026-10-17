"""Explicit function decorators. Model clients and business transports remain untouched."""
from functools import wraps
import inspect

from . import context
from .events import Span, operation, status
from .streams import AsyncStream, Stream


def instrument(collector, kind, worker, target=None, *, tag="task", task_id=None, carrier=None,
               capture="omit", classify=None):
    if not isinstance(worker, context.Worker) or (kind == "call" and not isinstance(target, context.Worker)):
        raise ValueError("task and call participants must be explicit Worker objects")
    operation(tag)
    context.identifier(task_id)
    if capture not in {"omit", "shape"}:
        raise ValueError("capture supports only omit or shape; values and exception text are never captured")
    if classify is not None and not callable(classify):
        raise ValueError("classify must be a result classifier or None")

    def classify_result(result):
        if classify is None:
            return "success"  # Callable completion; no claim about an uninspected HTTP response.
        try:
            outcome = classify(result)
            if outcome in {"success", "error", "unknown"}:
                return outcome
        except BaseException:
            pass
        collector._diagnostic("classification_failed")
        return "unknown"

    def decorate(function):
        def span():
            # Invalid supplied carriers produce an independent root, never a guessed relation.
            supplied_carrier = carrier
            if callable(carrier):
                try:
                    supplied_carrier = carrier()
                except BaseException:
                    collector._diagnostic("carrier_failed")
                    supplied_carrier = {}
            try:
                return Span(collector, kind, worker, target, tag, task_id, supplied_carrier, capture)
            except Exception:
                collector._fault("event_capture_failed")
                return None

        if inspect.isasyncgenfunction(function):
            @wraps(function)
            def async_generator(*arguments, **keywords):
                record = span()
                if record is None:
                    return function(*arguments, **keywords)
                return AsyncStream(function(*arguments, **keywords), record, len(arguments), len(keywords))
            return async_generator

        if inspect.isgeneratorfunction(function):
            @wraps(function)
            def generator(*arguments, **keywords):
                record = span()
                if record is None:
                    return function(*arguments, **keywords)
                return Stream(function(*arguments, **keywords), record, len(arguments), len(keywords))
            return generator

        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def asynchronous(*arguments, **keywords):
                record = span()
                if record is None:
                    return await function(*arguments, **keywords)
                token = context.current.set(record.context)
                try:
                    result = await function(*arguments, **keywords)
                except BaseException as error:
                    record.finish(status(error), len(arguments), len(keywords))
                    raise
                else:
                    record.finish(classify_result(result), len(arguments), len(keywords))
                    return result
                finally:
                    context.current.reset(token)
            return asynchronous

        @wraps(function)
        def synchronous(*arguments, **keywords):
            record = span()
            if record is None:
                return function(*arguments, **keywords)
            token = context.current.set(record.context)
            try:
                result = function(*arguments, **keywords)
            except BaseException as error:
                record.finish(status(error), len(arguments), len(keywords))
                raise
            else:
                record.finish(classify_result(result), len(arguments), len(keywords))
                return result
            finally:
                context.current.reset(token)
        return synchronous
    return decorate
