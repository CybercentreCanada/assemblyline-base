# Assemblyline Dev Setup (Kubernetes)
- Follow steps in [K8S appliance](https://github.com/CybercentreCanada/assemblyline-helm-chart/tree/master/appliance) for local Kubernetes setup
- Enable registry add-on for microk8s (other registries can be used like Harbor but involves more setup which isn't covered here)
  - Test: curl localhost:32000/v2/_catalog
- When ready to build, run local_dev_containers.sh script with tag as parameter
- Run helm install|upgrade using new tag in values.yaml
- Use Lens or command-line to monitor status of deployment
