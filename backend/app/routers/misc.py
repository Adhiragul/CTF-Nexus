from fastapi import APIRouter

from ..models import (
    BaseConvertRequest, JwtRequest, TimestampRequest, UuidRequest,
    UnicodeRequest, RegexRequest,
)
from ..plugins.misc.tools import (
    base_convert, decode_jwt, convert_timestamp, parse_uuid,
    unicode_inspect, regex_test,
)

router = APIRouter(prefix="/api/misc", tags=["misc"])


@router.post("/base-convert")
def base_convert_ep(req: BaseConvertRequest):
    return base_convert(req.value, req.from_base, req.to_base)


@router.post("/jwt-decode")
def jwt_decode_ep(req: JwtRequest):
    return decode_jwt(req.token)


@router.post("/timestamp")
def timestamp_ep(req: TimestampRequest):
    return convert_timestamp(req.value)


@router.post("/uuid")
def uuid_ep(req: UuidRequest):
    return parse_uuid(req.value)


@router.post("/unicode")
def unicode_ep(req: UnicodeRequest):
    return unicode_inspect(req.text)


@router.post("/regex")
def regex_ep(req: RegexRequest):
    return regex_test(req.pattern, req.text, req.flags)
