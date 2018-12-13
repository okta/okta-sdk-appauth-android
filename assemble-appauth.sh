#!/usr/bin/env bash

cd $1

if [ ! -f $2libs/appauth-release.aar ]; then
    ./gradlew assembleRelease
    mkdir $2/libs
    cp $1/library/build/outputs/aar/appauth-release.aar $2/libs/okta-appauth-fork.aar
fi