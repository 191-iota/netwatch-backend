#!/bin/bash
set -e

source .env

cross build --release --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/netwatch ${PI_USER}@${PI_HOST}:${PI_PATH}/
ssh ${PI_USER}@${PI_HOST} "sudo setcap cap_net_raw=eip ${PI_PATH}/netwatch"
scp deploy/netwatch.service $PI_USER@$PI_HOST:/tmp/
ssh $PI_USER@$PI_HOST "sudo mv /tmp/netwatch.service /etc/systemd/system/ && sudo systemctl daemon-reload"
echo "deployed. run: ssh ${PI_USER}@${PI_HOST} '${PI_PATH}/netwatch'"
ssh $PI_USER@$PI_HOST "sudo systemctl restart netwatch"
