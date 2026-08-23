# demo-K8s_network_policy

Demo for k8s NP

## Terraform Cloud / DigitalOcean

Le répertoire de travail Terraform Cloud est `01-tf_init_build`.

Variables à définir dans le workspace TFC :

- `do_token` : token API DigitalOcean, marqué comme sensible
- `entropy` : suffixe unique pour les noms de ressources
- `nb_clusters` : nombre de clusters
- `node_count` : nombre de nœuds dans chaque cluster
- `project_name` : nom du projet DigitalOcean existant, par exemple `LAB`

Les clusters sont associés au projet DigitalOcean indiqué par `project_name`.

`node_count` ne doit pas être ajouté dans `common.auto.tfvars`, afin que la valeur du workspace TFC soit utilisée.

Pour tester l'accès au service web dans le namespace du "target"

>kubectl run test-$RANDOM --rm -it --image=nicolaka/netshoot -l app=monlabel -- bash
>
>/ # curl http://svc-target.ns-target.svc.cluster.local
