# demo-K8s_network_policy

Demo for k8s NP

Pour tester l'accès au service web dans le namespace du "target"

>kubectl run test-$RANDOM --rm -it --image=alpine -- sh
>
>/ # wget -qO- --timeout=2 http://svc-target.ns-target.svc.cluster.local
