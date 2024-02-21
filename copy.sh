#!/bin/sh

#  copy.sh
#  
#
#  Created by Chris Coding on 2/2/24.
#

mkdir Payload

echo "[COPY BOOTSTRAP] copying Bootstrap.app over to Payload (3/7)"

cp -a .theos/obj/debug/install_Bootstrap/Applications/Bootstrap.app Payload
if [ -e Payload/Bootstrap.app ]
then
echo "[COPY BOOTSTRAP] Bootstrap copied to Payload!"

else
echo "[COPY BOOTSTRAP] ERR: unable to copy Bootstrap.app to Payload"
exit
fi



echo "[COPY BOOTSTRAP] making lib folder in Bootstrap.app.. (4/7)"

mkdir Payload/Bootstrap.app/include
mkdir Payload/Bootstrap.app/include/libs
mkdir Payload/Bootstrap.app/include/libs/SBtools

if [ -e Payload/Bootstrap.app/include/libs ]
then
echo "[COPY BOOTSTRAP] lib folder created, copying over dylibs (5/7)"

install -m755  Bootstrap/include/libs/launchdhooker/launchdhooker.dylib Payload/Bootstrap.app/include/libs/launchdhooker.dylib

install -m755  Bootstrap/include/libs/SBtools/sbtool/SBTool Payload/Bootstrap.app/include/libs/SBtools/SBTool

install -m755  Bootstrap/include/libs/SBtools/sbhooker/SBHooker.dylib Payload/Bootstrap.app/include/libs/SBHooker.dylib

cp  Bootstrap/include/libs/SBtools/sbtool/SpringBoardEnts.plist Payload/Bootstrap.app/include/libs/SBtools/SpringBoardEnts.plist

cp -r strapfiles Payload/Bootstrap.app

install -m755 roothelper/RootHelper Payload/Bootstrap.app/RootHelper

# we can just check if one of the dylibs exists & the SBents, then we'll be good
if [ -e Payload/Bootstrap.app/include/libs/launchdhooker.dylib ] && [ -e Payload/Bootstrap.app/include/libs/SBtools/SpringBoardEnts.plist ]
then
echo "[COPY BOOTSTRAP] dylibs have been copied over!"
else
echo "[COPY BOOTSTRAP] ERR: dylibs were unable to be copied over"
exit
fi

rm -rf Payload/Bootstrap.app/Bootstrap.app
echo "[COPY BOOTSTRAP] signing Bootstrap (6/7)"
ldid -Sentitlements.plist -Cadhoc Payload/Bootstrap.app/Bootstrap

echo "[COPY BOOTSTRAP] packaging Bootstrap as .tipa..(7/7)"
mkdir output
zip -vr9 output/BootstrapG.tipa Payload/ -x "*.DS_Store"
if [ -e output/BootstrapG.tipa ]
then
rm -rf Payload
rm -rf .theos
echo "[COPY BOOTSTRAP] BootstrapG.tipa created, exiting.."
exit
else
echo "[COPY BOOTSTRAP] ERR: unable to package into a tipa!"
exit
fi

else
echo "[COPY BOOTSTRAP] ERR: unable to create lib folder for dylibs"
exit
fi
