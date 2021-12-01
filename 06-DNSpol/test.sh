#!/bin/bash

echo "Test perdus.com"
echo "---"
kubectl exec -it test-pod -- curl -svL http://perdus.com

echo "---"
echo "Test perdu.com"
echo "---"
kubectl exec -it test-pod -- curl -svL http://perdu.com  --connect-timeout 2
