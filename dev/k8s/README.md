# Assemblyline Dev Setup (Kubernetes)
- Follow steps in [K8S appliance](https://github.com/CybercentreCanada/assemblyline-helm-chart/tree/master/appliance) for local Kubernetes setup
- Enable registry add-on for microK8S (other registries can be used like Harbor but involves more setup which isn't covered here)
  - Test: curl localhost:32000/v2/_catalog
- When ready to build, run local_dev_containers.sh script with tag as parameter.
- Run helm install|upgrade using new tags in values.yaml.
- Use Lens or kubectl to monitor status of deployment
- You can create local service-base images by passing an optional build-arg on a docker build command otherwise will pull latest.
  - ie. docker build . -f service-base.Dockerfile --build-arg build_no=dev0
- Debugging: Visual Code's [Bridge to Kubernetes](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.mindaro) &
[Kubernetes](https://marketplace.visualstudio.com/items?itemName=ms-kubernetes-tools.vscode-kubernetes-tools) extensions
  - TODO: figure out how to use it with Scaler/Updater that make calls to Kubernetes API
  - Add to settings.json (assuming using microk8s installed from snap):
    ```
    "vs-kubernetes": {
      "vs-kubernetes.namespace": "al",
      "vs-kubernetes.kubectl-path": "/snap/kubectl/current/kubectl",
      "vs-kubernetes.helm-path": "/snap/helm/current/helm",
      "vs-kubernetes.minikube-path": "/snap/bin/microk8s",
      "vs-kubernetes.kubectlVersioning": "user-provided",
      "vs-kubernetes.outputFormat": "yaml",
      "vs-kubernetes.kubeconfig": "/var/snap/microk8s/current/credentials/client.config",
      "vs-kubernetes.knownKubeconfigs": [],
      "vs-kubernetes.autoCleanupOnDebugTerminate": false,
      "vs-kubernetes.nodejs-autodetect-remote-root": true,
      "vs-kubernetes.nodejs-remote-root": "",
      "vs-kubernetes.nodejs-debug-port": 9229,
      "vs-kubernetes.local-tunnel-debug-provider": "",
      "checkForMinikubeUpgrade": false,
      "imageBuildTool": "Docker"
    }
    ```
