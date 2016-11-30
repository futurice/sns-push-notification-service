#! /usr/bin/env bash
cd push_service; zip -r "../sns-proxy-$(date +"%Y-%m-%d-%H-%M").zip" . -x "*.DS_Store" -x "push-service-env/*" -x "test*" -x "__pycache__/*"
