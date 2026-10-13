import hashlib

from fastapi import HTTPException


def fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
