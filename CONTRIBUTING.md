## How to Contribute

You are welcome to contribute to NetTracer. Use issues for discussing proposals or to raise a question. If you have improvements to NetTracer, please submit your pull request. For those just getting started, consult this [guide](https://help.github.com/articles/creating-a-pull-request-from-a-fork/).

## Local deployment environment setup necessary tools
* [Docker - One of containerization engines](https://docs.docker.com/engine/install/)
* [Minikube - local Kubernetes cluster](https://minikube.sigs.k8s.io/docs/start)
* [Kubectl - CLI tool for Kubernetes control](https://docs.docker.com/engine/install/)
* [DevSpace - Deploy & Develop Kubernetes Apps](https://devspace.sh/cli/docs/getting-started/installation/)
### Optional tools
* [Lens IDE - UI for kubectl commands](https://k8slens.dev)
## Quickstart

After installation of Docker and Minikube

```
minikube start --driver=docker
```

Inside repo folder run command and select branch:

```
devspace dev
```
It will take some time, project will be deployed into your local `minikube` cluster, and you will see deployment shell.
It's configured for a file sync between our Pods in k8s and your local project files.

To remove created resource
```
devspace purge
```
To stop, delete minikube cluster
```
minikube stop
minikube delete
```
