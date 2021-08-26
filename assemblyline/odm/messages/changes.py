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
    operation: Operation
    name: str

    @staticmethod
    def serialize(obj: ServiceChange) -> str:
        return json.dumps(asdict(obj))

    @staticmethod
    def deserialize(data: str) -> ServiceChange:
        return ServiceChange(**json.loads(data))
