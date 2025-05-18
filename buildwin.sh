# msys2 windows build script

echo "Build proxytunnel..."
make

echo "Build docs..."
make docs

echo "Copy msys/openssl dll to build dir..."
cp  /usr/bin/msys-2.0.dll /usr/bin/msys-crypto-3.dll /usr/bin/msys-ssl-3.dll /usr/bin/msys-z.dll .

echo "Generate proxytunnel.zip with docs, exe and msys/openssl dll..."
zip proxytunnel.zip proxytunnel.exe *.dll docs/proxytunnel.1 docs/proxytunnel.1.html docs/proxytunnel-paper.html

if [ ! -z "${TRAVIS_TAG}" ]; then 
echo "Deploy proxytunnel.zip to github release tag:${TRAVIS_TAG}..."
/usr/bin/bash ./deploy.sh "proxytunnel.zip"
fi
