#!/bin/bash

kubectl exec client-pod -- curl -sv svc-www.default.svc.cluster.local:8080/discount
