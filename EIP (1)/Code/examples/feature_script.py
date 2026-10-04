"""Feature script for `eip apply examples/feature_script.py Demo.exe`.

Must define build(app) -> eip.Feature. The CLI attaches to `app`, calls this,
installs the returned Feature, then detaches.
"""
from eip.types import ValueType


def build(app):
    count = app.value.read("Demo.exe!g_MenuCount", type=ValueType.I32)
    feature = app.feature.create("Export")
    feature.add_value(
        f"Demo.exe!g_MenuItems+0x{count * 16:x}",
        "Export",
        type=ValueType.CSTR_ASCII,
        capacity=16,
    )
    feature.add_value("Demo.exe!g_MenuCount", count + 1, type=ValueType.I32)
    feature.add_command("export")
    return feature
