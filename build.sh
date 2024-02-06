#! /bin/sh

SCRIPT_DIR=$( dirname -- "$( readlink -f -- "$0"; )"; )

echo "[MAKE BOOTSTRAP] making Bootstrap-G dylibs..(1/7)"
# Gonna build choma first
cd "$SCRIPT_DIR"
cd Bootstrap/include/choma
make clean && make

cd ../libs

cd launchdhooker
make clean && make

cd ../SBtools/sbtool
make clean && make

cd ../sbhooker
make clean && make

echo "[MAKE BOOTSTRAP] made dylibs, signing, then moving them now (2/7)"

cd "$SCRIPT_DIR"

./Bootstrap/include/choma/output/tests/ct_bypass -i Bootstrap/include/libs/launchdhooker/.theos/obj/debug/launchdhooker.dylib -r -o Bootstrap/include/libs/launchdhooker/launchdhooker.dylib

if [ -e Bootstrap/include/libs/launchdhooker/launchdhooker.dylib ]
then
rm -rf Bootstrap/include/libs/launchdhooker/.theos
else
echo "[MAKE BOOTSTRAP] ERR: launchdhooker.dylib wasn't moved/signed correctly"
exit
fi

./Bootstrap/include/choma/output/tests/ct_bypass -i Bootstrap/include/libs/SBtools/sbtool/.theos/obj/debug/SBTool -r -o Bootstrap/include/libs/SBtools/sbtool/SBTool

if [ -e Bootstrap/include/libs/SBtools/sbtool/SBTool ]
then
rm -rf Bootstrap/include/libs/SBtools/sbtool/.theos
else
echo "[MAKE BOOTSTRAP] ERR: SBTool wasn't moved/signed correctly"
exit
fi

cd "$SCRIPT_DIR"
./Bootstrap/include/choma/output/tests/ct_bypass -i Bootstrap/include/libs/SBtools/sbhooker/.theos/obj/debug/SBHooker.dylib -r -o Bootstrap/include/libs/SBtools/sbhooker/SBHooker.dylib

if [ -e Bootstrap/include/libs/SBtools/sbhooker/SBHooker.dylib ]
then
rm -rf Bootstrap/include/libs/SBtools/sbhooker/.theos
else
echo "[MAKE BOOTSTRAP] ERR: SBHooker.dylib wasn't moved/signed correctly"
exit
fi

# continue from here
echo "[MAKE BOOTSTRAP] dylibs moved & signed successfully, running [COPY BOOTSTRAP]"
cd "$SCRIPT_DIR"
chmod ++x copy.sh
./copy.sh


