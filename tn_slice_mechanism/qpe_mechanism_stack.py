"""SOURCE ONLY / NOT_RUN. Pinned stdlib JSON codec and tree equality without Python depth limits.

``dumps``/``loads`` first use the unchanged standard C codec, so every shallow record keeps
the exact v1 bytes and values. Only when that codec raises RecursionError (deep nesting)
does the bounded explicit-stack codec below run; it emits the identical compact, sorted,
ASCII bytes and builds the identical builtin value, or fails closed. No tree search,
optimizer, scoring, summary substitution or recursion-limit change is performed here.
"""
from __future__ import annotations

import json
import math

MAX_FALLBACK_BYTES = 64 << 20
MAX_DEPTH = 20000 + 64
MAX_EQUAL_ITEMS = 10_000_000
_FIRST, _KEY, _COLON, _VALUE, _AFTER = range(5)


class StackJSONError(ValueError):
    """Malformed, nonfinite, cyclic, oversize, too deep or non-builtin JSON; never coerced."""


def need(ok, message):
    if not ok:
        raise StackJSONError(message)


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise StackJSONError("nonfinite JSON constant")


def dumps(value):
    """Compact sorted ASCII JSON bytes, identical to the v1 ``json.dumps`` call."""
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")
    except RecursionError:
        return _encode(value)


def loads(raw, *, object_pairs_hook=None, parse_constant=None):
    """Strict JSON value from UTF-8 bytes or str; duplicate keys and NaN/Infinity are rejected.

    Caller hooks, when given, are used by both the C decoder and the deep fallback, so a
    caller's own duplicate-key/nonfinite error class and message are preserved.
    """
    need(type(raw) in (bytes, str), "exact JSON bytes or text required")
    text = raw.decode("utf-8") if type(raw) is bytes else raw
    hook = _pairs if object_pairs_hook is None else object_pairs_hook
    constant = _constant if parse_constant is None else parse_constant
    try:
        return json.loads(text, object_pairs_hook=hook, parse_constant=constant)
    except RecursionError:
        need(len(text) <= MAX_FALLBACK_BYTES, "deep JSON exceeds fallback byte bound")
        return _decode(text, hook, constant)


def _encode(value):
    out = bytearray()
    active = set()
    pending = [(0, value, 0)]  # 0 value, 1 literal bytes, 2 leave container
    while pending:
        op, item, depth = pending.pop()
        if op == 2:
            active.discard(item)
            continue
        if op == 1:
            raw = item
        else:
            kind = type(item)
            if kind is dict or kind is list or kind is tuple:
                need(depth <= MAX_DEPTH, "JSON nesting exceeds bound")
                identity = id(item)
                need(identity not in active, "cyclic JSON container")
                active.add(identity)
                pending.append((2, identity, depth))
                if kind is dict:
                    need(all(type(key) is str for key in item), "exact string JSON keys required")
                    names = sorted(item)
                    pending.append((1, b"}", depth))
                    for i in range(len(names) - 1, -1, -1):
                        key = names[i]
                        pending.append((0, item[key], depth + 1))
                        pending.append((1, b":", depth))
                        pending.append((1, json.dumps(key, ensure_ascii=True).encode("ascii"), depth))
                        if i:
                            pending.append((1, b",", depth))
                    raw = b"{"
                else:
                    pending.append((1, b"]", depth))
                    for i in range(len(item) - 1, -1, -1):
                        pending.append((0, item[i], depth + 1))
                        if i:
                            pending.append((1, b",", depth))
                    raw = b"["
            else:
                need(item is None or kind in (str, int, float, bool), "exact builtin JSON scalar required")
                need(kind is not float or math.isfinite(item), "finite JSON number required")
                raw = json.dumps(item, ensure_ascii=True, allow_nan=False).encode("ascii")
        need(len(out) + len(raw) <= MAX_FALLBACK_BYTES, "deep JSON exceeds fallback byte bound")
        out.extend(raw)
    return bytes(out)


def _decode(text, hook, constant):
    scan = json.JSONDecoder(object_pairs_hook=hook, parse_constant=constant).raw_decode
    # Frame: [items, is_dict, state, pending_key, parent_frame_or_None]. Objects collect
    # ordered (key, value) pairs and pass them to the caller hook when closed, exactly as
    # the C decoder does; values of nested objects are attached when their frame closes.
    frames = []
    root, have_root, pos, length = None, False, 0, len(text)

    def attach(value):
        nonlocal root, have_root
        if frames:
            frame = frames[-1]
            if frame[1]:
                frame[0].append((frame[3], value))
            else:
                frame[0].append(value)
            frame[2] = _AFTER
        else:
            root, have_root = value, True

    while True:
        while pos < length and text[pos] in " \t\n\r":
            pos += 1
        if not frames:
            if have_root:
                need(pos == length, "trailing JSON data")
                return root
            need(pos < length, "missing JSON value")
        else:
            need(pos < length, "truncated JSON value")
            frame = frames[-1]
            is_dict, state = frame[1], frame[2]
            char = text[pos]
            close = "}" if is_dict else "]"
            if (state == _AFTER or state == _FIRST) and char == close:
                frames.pop()
                pos += 1
                attach(hook(frame[0]) if is_dict else frame[0])
                continue
            if state == _AFTER:
                need(char == ",", "JSON comma or close required")
                frame[2] = _KEY if is_dict else _VALUE
                pos += 1
                continue
            if is_dict and state in (_FIRST, _KEY):
                need(char == '"', "JSON string object key required")
                key, pos = scan(text, pos)
                need(type(key) is str, "JSON string object key required")
                frame[3], frame[2] = key, _COLON
                continue
            if state == _COLON:
                need(char == ":", "JSON colon required")
                frame[2] = _VALUE
                pos += 1
                continue
        char = text[pos]
        if char == "[" or char == "{":
            need(len(frames) < MAX_DEPTH, "JSON nesting exceeds bound")
            frames.append([[], char == "{", _FIRST, None])
            pos += 1
            continue
        need(char not in "]},:", "unexpected JSON punctuation")
        value, pos = scan(text, pos)
        need(type(value) in (str, int, float, bool) or value is None, "JSON scalar required")
        need(type(value) is not float or math.isfinite(value), "overflowed JSON number")
        attach(value)


def copy(value, *, check=None):
    """Iterative deep copy of builtin dict/list/tuple data; equal to ``copy.deepcopy``.

    Insertion order and container types are preserved. Immutable scalars are shared
    (as deepcopy does). Any other object is handed to ``copy.deepcopy`` unchanged.
    Cycles fail closed rather than being memoized.
    """
    import copy as _copy
    root = [None]
    pending = [(0, value, root, 0)]  # 0 enter, 1 freeze tuple, 2 leave container
    active = set()
    count = 0
    while pending:
        if check is not None:
            check()
        op, item, parent, slot = pending.pop()
        if op == 2:
            active.discard(item)
            continue
        if op == 1:
            parent[slot] = tuple(item)
            continue
        count += 1
        need(count <= MAX_EQUAL_ITEMS, "copy item budget exceeded")
        kind = type(item)
        if kind is dict or kind is list or kind is tuple:
            identity = id(item)
            need(identity not in active, "cyclic builtin container")
            active.add(identity)
            pending.append((2, identity, None, 0))
            if kind is dict:
                out = {key: None for key in item}
                parent[slot] = out
                for key in reversed(list(item)):
                    pending.append((0, item[key], out, key))
            else:
                out = [None] * len(item)
                if kind is tuple:
                    pending.append((1, out, parent, slot))
                else:
                    parent[slot] = out
                for i in range(len(item) - 1, -1, -1):
                    pending.append((0, item[i], out, i))
        elif item is None or kind in (str, int, float, bool, bytes):
            parent[slot] = item
        else:
            parent[slot] = _copy.deepcopy(item)
    return root[0]


def equal(left, right):
    """Exact type-sensitive structural equality for nested tuple/list trees, iteratively."""
    pending = [(left, right)]
    count = 0
    while pending:
        a, b = pending.pop()
        count += 1
        need(count <= MAX_EQUAL_ITEMS, "tree equality budget exceeded")
        kind = type(a)
        if kind is not type(b):
            return False
        if kind is tuple or kind is list:
            if len(a) != len(b):
                return False
            pending.extend(zip(a, b))
        elif kind is dict:
            if a.keys() != b.keys():
                return False
            pending.extend((a[key], b[key]) for key in a)
        elif not a == b:
            return False
    return True
