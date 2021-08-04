# Assemblyline Dev Setup (Kubernetes)
- Follow steps in [K8S appliance](https://github.com/CybercentreCanada/assemblyline-helm-chart/tree/master/appliance) for local Kubernetes setup
- Enable registry add-on for microK8S (other registries can be used like Harbor but involves more setup which isn't covered here)
  - Test: curl localhost:32000/v2/_catalog
- When ready to build, run local_dev_containers.sh script with tag as parameter
- Run helm install|upgrade using new tag in values.yaml
- Use Lens, command-line, or VS Code's [Kubernetes](https://marketplace.visualstudio.com/items?itemName=ms-kubernetes-tools.vscode-kubernetes-tools) extension to monitor status of and/or debug deployment
- You can create local service-base images by passing a build-arg on a docker build command
  - ie. docker build . -f service-base.Dockerfile --build-arg dev0
