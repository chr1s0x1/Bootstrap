TARGET := iphone:clang:16.5:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TOOL_NAME = RootHelper

RootHelper_FILES = $(wildcard *.m) Exploits/fastPathSign/src/coretrust_bug.c Exploits/fastPathSign/src/codesign.m optool/operations.m
RootHelper_LDFLAGS = -Lexternal/lib -lcrypto -lchoma
RootHelper_CFLAGS = -fobjc-arc $(shell pkg-config --cflags libcrypto) -Iexternal/include -Wmissing-braces -IExploits/fastPathSign/src
RootHelper_CODESIGN_FLAGS = -Sentitlements.plist
RootHelper_INSTALL_PATH = /usr/local/bin
RootHelper_LIBRARIES = archive
RootHelper_PRIVATE_FRAMEWORKS = SpringBoardServices BackBoardServices MobileCoreServices MobileContainerManager IOKit

include $(THEOS_MAKE_PATH)/tool.mk
