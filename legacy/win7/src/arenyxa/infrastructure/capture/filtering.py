from __future__ import annotations

import re
from arenyxa.compat import dataclass
from typing import Any, Callable

from arenyxa.domain.models import NetworkEvent

EventPredicate = Callable[[NetworkEvent], bool]

TOKEN_RE = re.compile(
    r'\s*(?:(?P<number>\d+(?:\.\d+)?)|(?P<string>"(?:\\.|[^"\\])*")|'
    r"(?P<op>==|!=|>=|<=|>|<)|(?P<word>[A-Za-z_][\w.:-]*|&&|\|\||\[|\]|,|\(|\)))"
)


class FilterSyntaxError(ValueError):
    pass


@dataclass(slots=True)
class Token:
    kind: str
    value: str


def tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    position = 0
    while position < len(expression):
        match = TOKEN_RE.match(expression, position)
        if not match:
            raise FilterSyntaxError(f"invalid token at {position}")
        kind = match.lastgroup or "word"
        tokens.append(Token(kind, match.group(kind)))
        position = match.end()
    return tokens


class FilterEngine:
    

    def compile(self, expression: str) -> EventPredicate:
        if not expression.strip():
            return lambda event: True
        tokens = tokenize(expression)
        position = 0

        def peek(value: str | None = None) -> bool:
            if position >= len(tokens):
                return False
            return value is None or tokens[position].value == value

        def take(value: str | None = None) -> Token:
            nonlocal position
            if position >= len(tokens) or (value is not None and tokens[position].value != value):
                raise FilterSyntaxError(f"expected {value or 'token'}")
            result = tokens[position]
            position += 1
            return result

        def literal() -> Any:
            token = take()
            if token.kind == "number":
                return float(token.value) if "." in token.value else int(token.value)
            if token.kind == "string":
                import json

                return json.loads(token.value)
            if token.value == "[":
                values = []
                while not peek("]"):
                    values.append(literal())
                    if peek(","):
                        take(",")
                    elif not peek("]"):
                        raise FilterSyntaxError("expected comma")
                take("]")
                return values
            return token.value

        def predicate() -> EventPredicate:
            field = take().value
            operator = take().value
            if operator in {"contains", "startsWith", "endsWith", "in"}:
                pass
            elif operator not in {"==", "!=", ">", "<", ">=", "<="}:
                raise FilterSyntaxError(f"unsupported operator: {operator}")
            expected = literal()

            def evaluate(event: NetworkEvent) -> bool:
                actual = self._field(event, field)
                if operator == "==":
                    return bool(actual == expected)
                if operator == "!=":
                    return bool(actual != expected)
                if operator == ">":
                    return actual is not None and bool(actual > expected)
                if operator == "<":
                    return actual is not None and bool(actual < expected)
                if operator == ">=":
                    return actual is not None and bool(actual >= expected)
                if operator == "<=":
                    return actual is not None and bool(actual <= expected)
                if operator == "contains":
                    return str(expected) in str(actual or "")
                if operator == "startsWith":
                    return str(actual or "").startswith(str(expected))
                if operator == "endsWith":
                    return str(actual or "").endswith(str(expected))
                if operator == "in":
                    return actual in expected
                return False

            return evaluate

        def factor() -> EventPredicate:
            if peek("("):
                take("(")
                expression_fn = disjunction()
                take(")")
                return expression_fn
            return predicate()

        def conjunction() -> EventPredicate:
            functions = [factor()]
            while peek("&&"):
                take("&&")
                functions.append(factor())
            return lambda event: all(function(event) for function in functions)

        def disjunction() -> EventPredicate:
            functions = [conjunction()]
            while peek("||"):
                take("||")
                functions.append(conjunction())
            return lambda event: any(function(event) for function in functions)

        result = disjunction()
        if position != len(tokens):
            raise FilterSyntaxError("unexpected trailing tokens")
        return result

    @staticmethod
    def _field(event: NetworkEvent, path: str) -> Any:
        mapping = {
            "protocol": event.protocol,
            "direction": event.direction,
            "bytes": event.size,
            "http.method": event.method,
            "http.url": event.url,
            "http.host": event.host,
            "http.status": event.status,
            "process.name": event.process_ref,
            "remote.port": event.metadata.get("remote_port"),
            "local.port": event.metadata.get("local_port"),
            "dns.qname": event.metadata.get("dns_qname"),
            "tls.version": event.metadata.get("tls_version"),
        }
        return mapping.get(path, event.metadata.get(path))
