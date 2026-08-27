from __future__ import annotations

__dynamic_exports__ = True

from arenyxa.qt_compat import binding_module
from arenyxa.qt_compat._helpers import class_with_scopes, export_public

_base = binding_module("QtWidgets")
export_public(_base, globals())

QApplication = class_with_scopes(_base.QApplication, {}, ensure_exec=True)
QBoxLayout = class_with_scopes(_base.QBoxLayout, {
    "Direction": {
        "LeftToRight":"LeftToRight",
        "RightToLeft":"RightToLeft",
        "TopToBottom":"TopToBottom",
        "BottomToTop":"BottomToTop",
    }
})
QDialog = class_with_scopes(_base.QDialog, {"DialogCode": {"Accepted":"Accepted","Rejected":"Rejected"}}, ensure_exec=True)
QMessageBox = class_with_scopes(_base.QMessageBox, {
    "Icon": {"Information":"Information","Question":"Question","Warning":"Warning"},
    "StandardButton": {"Cancel":"Cancel","No":"No","Yes":"Yes"},
}, ensure_exec=True)
QDialogButtonBox = class_with_scopes(_base.QDialogButtonBox, {
    "ButtonRole": {"AcceptRole":"AcceptRole","RejectRole":"RejectRole"},
    "StandardButton": {"Cancel":"Cancel","Ok":"Ok","Save":"Save"},
})
QAbstractItemView = class_with_scopes(_base.QAbstractItemView, {
    "EditTrigger": {"NoEditTriggers":"NoEditTriggers"},
    "SelectionBehavior": {"SelectRows":"SelectRows"},
    "SelectionMode": {"ExtendedSelection":"ExtendedSelection","NoSelection":"NoSelection","SingleSelection":"SingleSelection"},
})
QFrame = class_with_scopes(_base.QFrame, {
    "Shadow": {"Plain":"Plain"},
    "Shape": {"NoFrame":"NoFrame","VLine":"VLine"},
})
QScrollArea = class_with_scopes(_base.QScrollArea, {"Shape": {"NoFrame":"NoFrame"}})
QHeaderView = class_with_scopes(_base.QHeaderView, {"ResizeMode": {"ResizeToContents":"ResizeToContents","Stretch":"Stretch"}})
QLineEdit = class_with_scopes(_base.QLineEdit, {"EchoMode": {"Password":"Password","Normal":"Normal"}})
QSizePolicy = class_with_scopes(_base.QSizePolicy, {"Policy": {"Expanding":"Expanding","Fixed":"Fixed"}})
QSystemTrayIcon = class_with_scopes(_base.QSystemTrayIcon, {"ActivationReason": {"Trigger":"Trigger"}})

                                                                                           
                                                                                            
QMenu = class_with_scopes(_base.QMenu, {}, ensure_exec=True)
