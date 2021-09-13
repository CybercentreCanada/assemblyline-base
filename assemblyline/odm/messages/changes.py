"""
Messages about configuration changes internal to assemblyline.

Uses standard library 
"""
from __future__ import annotations
import enum
import json
from dataclasses import asdict, dataclass


class Operation(enum.IntEnum):
    Added = 1
    Removed = 2
    Modified = 3


@dataclass
class ServiceChange:
    name: str
    operation: Operation

    @staticmethod
    def serialize(obj: ServiceChange) -> str:
        return json.dumps(asdict(obj))

    @staticmethod
    def deserialize(data: str) -> ServiceChange:
        return ServiceChange(**json.loads(data))

@dataclass
class SignatureChange:
    signature_id: str
    signature_type: str
    source: str
    operation: Operation

    @staticmethod
    def serialize(obj: SignatureChange) -> str:
        return json.dumps(asdict(obj))

    @staticmethod
    def deserialize(data: str) -> SignatureChange:
        return SignatureChange(**json.loads(data))
