#!/bin/bash

set -a 
source .env
set +a
python3 -m flask run --host=192.168.43.205 --port=5000