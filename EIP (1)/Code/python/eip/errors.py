"""EIP exception hierarchy.

Every exception here maps 1:1 to an eip::ErrorCode on the native side (see
core/include/eip/common.h). _native.py raises the matching class whenever a
C ABI call returns a non-zero eip_status, with the detail string retrieved
from eip_last_error_detail().
"""


class EipException(Exception):
    """Base class for every exception raised by the EIP Python API."""

    code = 0

    def __init__(self, detail: str = ""):
        self.detail = detail
        # `detail` normally already arrives as "CODE: message (extra)" from
        # eip_last_error_detail(); avoid stuttering the class name on top of it.
        msg = detail if detail else self.__class__.__name__
        super().__init__(msg)


class ProcessNotFound(EipException):
    code = 1


class ProcessAccessDenied(EipException):
    code = 2


class ProcessAlreadyAttached(EipException):
    code = 3


class ProcessNotAttached(EipException):
    code = 4


class ModuleNotFound(EipException):
    code = 10


class AddressInvalid(EipException):
    code = 20


class MemoryReadFailed(EipException):
    code = 21


class MemoryWriteFailed(EipException):
    code = 22


class MemoryProtectFailed(EipException):
    code = 23


class MemoryAllocFailed(EipException):
    code = 24


class ValueTypeMismatch(EipException):
    code = 30


class ValueTargetUnresolved(EipException):
    code = 31


class FunctionNotFound(EipException):
    code = 40


class FunctionTooSmallToHook(EipException):
    code = 41


class FunctionAlreadyHooked(EipException):
    code = 42


class FunctionNotHooked(EipException):
    code = 43


class HookInstallFailed(EipException):
    code = 50


class HookRemoveFailed(EipException):
    code = 51


class PatchConflict(EipException):
    code = 60


class PatchNotFound(EipException):
    code = 61


class TransactionFailed(EipException):
    code = 70


class TransactionAlreadyCommitted(EipException):
    code = 71


class TransactionEmpty(EipException):
    code = 72


class UnsupportedPE(EipException):
    code = 80


class PEParseFailed(EipException):
    code = 81


class PEWriteFailed(EipException):
    code = 82


class ArchitectureMismatch(EipException):
    code = 90


class FeatureInstallError(EipException):
    code = 100


class FeatureNotFound(EipException):
    code = 101


class FeatureAlreadyInstalled(EipException):
    code = 102


class IoError(EipException):
    code = 110


class NotImplementedOnPlatform(EipException):
    code = 111


class InvalidArgument(EipException):
    code = 112


class InternalError(EipException):
    code = 120


_BY_CODE = {cls.code: cls for cls in EipException.__subclasses__()}


def raise_for_code(code: int, detail: str) -> None:
    if code == 0:
        return
    cls = _BY_CODE.get(code, EipException)
    exc = cls(detail)
    exc.code = code
    raise exc
