# Rotate Kubernetes service account credentials

This is an experimental controller to see what it would take to rotate Kubernetes service account credentials.

NOTE: This project doesn't work currently due to a bug in Kubernetes ([issue 40411](https://github.com/kubernetes/kubernetes/issues/40411)). 

## Strategy

* Create a second secret for all service accounts.
* Restart pods that use the original secret.
* Rotate service account secrets, creating a new one and deleting the original.

## Example

Create a service account and some pods that mount it.

```
kubectl create namespace test
kubectl create serviceaccount -n test dotherobot
kubectl create -n test -f examples/deployment.yaml
```

Run the service account rotator (these flags assume you're using minikube locally).

```
kube-service-account-rotator \
    --kubeconfig "/root/.kube/config" \
    --root-ca "/root/.minikube/ca.crt" \
    --signing-key "/root/.minikube/apiserver.key" \
    --rotation-frequency "1m" \
    --namespace "test" \
    run
```

The service account credentials will then be rotated every minute.

View which pods mount which secrets use the following `jq` fu:

```
kubectl get pods -n test -o json | jq -r '.items[] | "\(.metadata.name) \(.spec.volumes[].name)"'
```
