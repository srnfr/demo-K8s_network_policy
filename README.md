# demo-K8s_network_policy

Demo for k8s NP

Pour tester l'accès au service web dans le namespace du "target"

>kubectl run test-$RANDOM --rm -it --image=nicolaka/netshoot -l app=monlabel -- bash
>
>/ # curl http://svc-target.ns-target.svc.cluster.local
