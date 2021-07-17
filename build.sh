#!/bin/bash 

function buildaction(){
    buildcmd="python3 setup.py sdist bdist_wheel"
    rmbuild="rm -rf build/ dist/ python3_libraccoon.egg-info/"
    uploadcmd="twine upload dist/*"
    
    if [ -z $1 ]
    then
        echo "Missing request argument required arguments include(build, rmbuild, upload)"
    else
        if [ $1 == "build" ]
        then
            $buildcmd
            
        elif [ $1 = "rmbuild" ]
        then
            $rmbuild
            
        elif [ $1 = "upload" ]
        then
            $uploadcmd
            
        else
            echo "Invalid argument give"
        fi
    fi
}

buildaction $1
