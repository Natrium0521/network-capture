# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'c:\Users\15838.LAPTOP-D8U5EVDM\Desktop\network-capture\src\resources\ui\main_window.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(933, 728)
        MainWindow.setAutoFillBackground(False)
        MainWindow.setStyleSheet("")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSpacing(10)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_0 = QtWidgets.QLabel(self.centralwidget)
        self.label_0.setMinimumSize(QtCore.QSize(30, 0))
        self.label_0.setAlignment(QtCore.Qt.AlignCenter)
        self.label_0.setWordWrap(False)
        self.label_0.setObjectName("label_0")
        self.horizontalLayout.addWidget(self.label_0)
        self.IfaceInput = QtWidgets.QComboBox(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.IfaceInput.sizePolicy().hasHeightForWidth())
        self.IfaceInput.setSizePolicy(sizePolicy)
        self.IfaceInput.setMaxVisibleItems(20)
        self.IfaceInput.setObjectName("IfaceInput")
        self.IfaceInput.addItem("")
        self.horizontalLayout.addWidget(self.IfaceInput)
        self.ActionBtn = QtWidgets.QPushButton(self.centralwidget)
        self.ActionBtn.setObjectName("ActionBtn")
        self.horizontalLayout.addWidget(self.ActionBtn)
        self.ClearBtn = QtWidgets.QPushButton(self.centralwidget)
        self.ClearBtn.setObjectName("ClearBtn")
        self.horizontalLayout.addWidget(self.ClearBtn)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setSpacing(10)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_1 = QtWidgets.QLabel(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_1.sizePolicy().hasHeightForWidth())
        self.label_1.setSizePolicy(sizePolicy)
        self.label_1.setMinimumSize(QtCore.QSize(30, 0))
        self.label_1.setAlignment(QtCore.Qt.AlignCenter)
        self.label_1.setObjectName("label_1")
        self.horizontalLayout_2.addWidget(self.label_1)
        self.FilterInput = QtWidgets.QLineEdit(self.centralwidget)
        self.FilterInput.setClearButtonEnabled(True)
        self.FilterInput.setObjectName("FilterInput")
        self.horizontalLayout_2.addWidget(self.FilterInput)
        self.FilterBtn = QtWidgets.QPushButton(self.centralwidget)
        self.FilterBtn.setObjectName("FilterBtn")
        self.horizontalLayout_2.addWidget(self.FilterBtn)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.splitter_2 = QtWidgets.QSplitter(self.centralwidget)
        self.splitter_2.setOrientation(QtCore.Qt.Vertical)
        self.splitter_2.setChildrenCollapsible(False)
        self.splitter_2.setObjectName("splitter_2")
        self.PacketTable = QtWidgets.QTableWidget(self.splitter_2)
        self.PacketTable.setEnabled(True)
        self.PacketTable.setMinimumSize(QtCore.QSize(0, 150))
        self.PacketTable.setAutoFillBackground(False)
        self.PacketTable.setStyleSheet("font: 9pt \"Consolas\";\n"
"")
        self.PacketTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.PacketTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.PacketTable.setShowGrid(False)
        self.PacketTable.setObjectName("PacketTable")
        self.PacketTable.setColumnCount(7)
        self.PacketTable.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        self.PacketTable.setHorizontalHeaderItem(6, item)
        self.PacketTable.horizontalHeader().setVisible(True)
        self.PacketTable.horizontalHeader().setCascadingSectionResizes(False)
        self.PacketTable.horizontalHeader().setSortIndicatorShown(False)
        self.PacketTable.horizontalHeader().setStretchLastSection(False)
        self.PacketTable.verticalHeader().setVisible(False)
        self.PacketTable.verticalHeader().setDefaultSectionSize(20)
        self.PacketTable.verticalHeader().setMinimumSectionSize(20)
        self.splitter = QtWidgets.QSplitter(self.splitter_2)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setObjectName("splitter")
        self.PacketTree = QtWidgets.QTreeWidget(self.splitter)
        self.PacketTree.setMinimumSize(QtCore.QSize(400, 150))
        self.PacketTree.setStyleSheet("font: 9pt \"Consolas\";")
        self.PacketTree.setObjectName("PacketTree")
        self.PacketTree.header().setVisible(False)
        self.PacketHex = QtWidgets.QPlainTextEdit(self.splitter)
        self.PacketHex.setMinimumSize(QtCore.QSize(510, 150))
        self.PacketHex.setStyleSheet("font: 9pt \"Consolas\";")
        self.PacketHex.setReadOnly(True)
        self.PacketHex.setPlainText("")
        self.PacketHex.setObjectName("PacketHex")
        self.verticalLayout_2.addWidget(self.splitter_2)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 933, 23))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "网络捕获"))
        self.label_0.setText(_translate("MainWindow", "网卡"))
        self.IfaceInput.setItemText(0, _translate("MainWindow", "未选择"))
        self.ActionBtn.setText(_translate("MainWindow", "开始捕获"))
        self.ClearBtn.setText(_translate("MainWindow", "清空"))
        self.label_1.setText(_translate("MainWindow", "过滤"))
        self.FilterBtn.setText(_translate("MainWindow", "应用过滤器"))
        self.PacketTable.setSortingEnabled(False)
        item = self.PacketTable.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "No."))
        item = self.PacketTable.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))
        item = self.PacketTable.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Source"))
        item = self.PacketTable.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.PacketTable.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.PacketTable.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Length"))
        item = self.PacketTable.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Summary"))
        self.PacketTree.headerItem().setText(0, _translate("MainWindow", "Root"))
