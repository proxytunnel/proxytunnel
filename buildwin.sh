# msys2 windows build script

echo "Build docs..."
make -C docs

echo "Build proxytunnel..."
make -f Makefile
strip -s proxytunnel.exe

echo "Generate proxytunnel.zip with docs, exe and msys/openssl dll..."
zip proxytunnel.zip proxytunnel.exe docs/proxytunnel.1 docs/proxytunnel.1.html docs/proxytunnel-paper.html
DLLS="$(ldd proxytunnel.exe | grep msys.*\.dll | awk '{print $3}' | xargs) /usr/lib/ossl-modules/legacy.dll"
zip proxytunnel.zip -j $DLLS 

if [ ! -z "${TRAVIS_TAG}" ]; then 
echo "Deploy proxytunnel.zip to github release tag:${TRAVIS_TAG}..."
/usr/bin/bash ./deploy.sh "proxytunnel.zip"
fi
