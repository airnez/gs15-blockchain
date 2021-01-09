#!/usr/bin/bash

pip install virtualenv

if [ $? -ne 0 ];then
  pip3 install virtualenv
fi
virtualenv -p python3 ./derouet_irenee_venv
source ./derouet_irenee_venv/bin/activate

pip install -r requirements.txt

if [ $? -ne 0 ];then
  pip3 install -r requirements.txt
fi

echo "all packages installed, activate the virtual environment
      with  : 'source ./derouet_irenee_venv/bin/activate'"
