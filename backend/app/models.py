from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class CryptoRequest(BaseModel):
    text: str


class WebRequest(BaseModel):
    url: str


class BaseConvertRequest(BaseModel):
    value: str
    from_base: int
    to_base: int


class JwtRequest(BaseModel):
    token: str


class TimestampRequest(BaseModel):
    value: str


class UuidRequest(BaseModel):
    value: str


class UnicodeRequest(BaseModel):
    text: str


class RegexRequest(BaseModel):
    pattern: str
    text: str
    flags: Optional[str] = None


class FlagProfileCreate(BaseModel):
    name: str
    prefix: Optional[str] = None
    custom_regex: Optional[str] = None


class FlagScanRequest(BaseModel):
    text: str
