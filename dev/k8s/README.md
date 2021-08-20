# Assemblyline Dev Setup (Kubernetes)
- Run setup script for [Assemblyline Development](https://github.com/CybercentreCanada/assemblyline-development-setup)
- When ready to build, run local_dev_containers.sh script with tag as parameter.
- Run helm upgrade using new tags in values.yaml.
- Use Lens or kubectl to monitor status of deployment
- You can create local service-base images by passing an optional build-arg on a docker build command otherwise will pull latest.
  - ie. docker build . -f service-base.Dockerfile --build-arg build_no=dev0
