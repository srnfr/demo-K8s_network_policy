# demo-K8s_network_policy

Demo for k8s NP

Pour tester l'accès au service web dans le namespace nommé "playerX"

>kubectl run --generator=run-pod/v1 test-$RANDOM --rm -i -t --image=alpine -- sh
 >/ # wget -qO- --timeout=2 http://web.nsplayerX.svc.cluster.local
