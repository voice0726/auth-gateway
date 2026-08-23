# 適用手順例

kubectl apply -f kube/namespace.yaml
kubectl apply -f kube/data-persistentvolumeclaim.yaml
kubectl apply -f kube/db-deployment.yaml
kubectl apply -f kube/db-service.yaml
kubectl apply -f kube/redis-deployment.yaml
kubectl apply -f kube/redis-service.yaml
kubectl apply -f kube/redis-configmap.yaml
kubectl apply -f kube/gateway-configmap.yaml
kubectl apply -f kube/gateway-deployment.yaml
kubectl apply -f kube/gateway-service.yaml
kubectl apply -f kube/zitadel-statefulset.yaml
kubectl apply -f kube/zitadel-service.yaml
kubectl apply -f kube/login-service.yaml
