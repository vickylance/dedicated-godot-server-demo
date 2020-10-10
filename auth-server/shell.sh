#!/bin/bash

source ~/.bashrc
export NVS_HOME="$HOME/.nvs"
git clone https://github.com/jasongin/nvs "$NVS_HOME"
. "$NVS_HOME/nvs.sh" install
nvs add lts
nvs use lts
nvs link lts
npm install
npm start
