#!/usr/bin/bash
# Travis-CI Deploy script to github release.
# 
# To use this script:
# - You must generate 'Personal access token' with repo scope of this repository.
# - You must add Variable GITHUB_UPLOAD_TOKEN in settings of your project in travis setting.
# - GITHUB_UPLOAD_TOKEN must contain the token.
# - You can create the token on 'machine user' in place of the 'owner user' of this repository for more security.
# 
# https://developer.github.com/v3/guides/managing-deploy-keys/#machine-users
# https://developer.github.com/changes/2020-02-14-deprecating-password-auth/
# https://docs.github.com/en/rest/overview/resources-in-the-rest-api#authentication
# https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token
#
# Syntax usage: 
# ./deploy.sh <file name to upload to release>

echo "Start try upload asset to github release at $(date)..."

if [ -z "${GITHUB_UPLOAD_TOKEN}" ]; then
  echo "GITHUB_UPLOAD_TOKEN are null, you must create Github Personal Access Token to use this script...";
  exit 4;
fi


if [ -z "${TRAVIS_TAG}" ]; then
  echo "TRAVIS_TAG is null!";
  exit 4;
fi

if [ -z "${TRAVIS_REPO_SLUG}" ]; then
  echo "TRAVIS_REPO_SLUG is null!";
  exit 4;
fi

if [ ! -f $1 ]; then
  echo "No file '$1' found...";
  exit 3;
fi

echo "Git TAG:"$TRAVIS_TAG
echo "Github SLUG:"$TRAVIS_REPO_SLUG
echo "File to Upload:"$1

ASSETTAGID=$(curl --no-progress-meter -q -H "Authorization: token ${GITHUB_UPLOAD_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        https://api.github.com/repos/${TRAVIS_REPO_SLUG}/releases/tags/${TRAVIS_TAG} | awk '/"assets": /{flag=1}/"id": /{sub(",$","",$2);id=$2;}/"name": /{sub("^\"","",$2); sub("\",$","",$2);name=$2; if (name=="'"$1"'") {print id;exit}}')
ASSETURL=$(curl --no-progress-meter -q -H "Authorization: token ${GITHUB_UPLOAD_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        https://api.github.com/repos/${TRAVIS_REPO_SLUG}/releases/tags/${TRAVIS_TAG} | awk '/"assets_url": /{sub("^\"","",$2); sub("\",$","",$2); sub("^https://api[.]","https://uploads.",$2);print $2;exit}')

if [ -z "${ASSETURL}" ]; then
        curl --no-progress-meter -q -H "Authorization: token ${GITHUB_UPLOAD_TOKEN}" \
                      -H "Accept: application/vnd.github.v3+json" \
                      https://api.github.com/repos/${TRAVIS_REPO_SLUG}/releases/tags/${TRAVIS_TAG}
        echo "Tag : ${TRAVIS_TAG} not found on project: ${TRAVIS_REPO_SLUG} at $(date)..."
        exit 3
fi

if [ ! -z "$ASSETTAGID" ]; then
        echo "Asset $1 are already uploaded on Tag: ${TRAVIS_TAG}!"
        echo "I must Delete $1 before upload..."
        curl  -H "Authorization: token ${GITHUB_UPLOAD_TOKEN}" \
              -X DELETE \
              -H "Accept: application/vnd.github.v3+json" \
              https://api.github.com/repos/${TRAVIS_REPO_SLUG}/releases/assets/${ASSETTAGID}
        if [ $? -eq 0 ]; then echo "Delete done!"
        else echo "Delete failed at $(date)!"; exit 1; fi
fi

echo "Uploading asset $1 to ${TRAVIS_REPO_SLUG} on tag: ${TRAVIS_TAG}..."
curl  --no-progress-meter -q -H "Authorization: token ${GITHUB_UPLOAD_TOKEN}" \
      -X POST \
      --data-binary @$1 \
      -H "Content-Type: application/zip" \
      -H "Accept: application/vnd.github.v3+json" \
      $ASSETURL?name=$1 >response.json
if [ $? -eq 0 ]; then echo "Success upload of asset $1 to ${TRAVIS_REPO_SLUG} on tag: ${TRAVIS_TAG} at $(date)...";
else cat response.json; echo "Failed upload of upload asset $1 to ${TRAVIS_REPO_SLUG} on tag: ${TRAVIS_TAG} at $(date)..."; exit 2; fi

echo "End upload asset $1 to '${TRAVIS_REPO_SLUG}' on tag: '${TRAVIS_TAG}' at $(date)..."
exit 0;
