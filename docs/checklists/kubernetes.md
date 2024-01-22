---
layout: default
title: Kubernetes
parent: Checklists
---

# Усиление Kuberneties для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Kuberneties для DevSecOps


### Ограничьте доступ к API Kubernetes для определенных диапазонов IP-адресов



`kubectl edit svc/kubernetes` <br> Обновите `spec.loadBalancerSourceRanges`



### Используйте контроль доступа на основе ролей (RBAC)


```
kubectl create serviceaccount <name> <br> kubectl create clusterrolebinding <name> --clusterrole=<role> --serviceaccount=<namespace>:<name>
```


### Включите PodSecurityPolicy (PSP)	

```
kubectl create serviceaccount psp-sa <br> kubectl create clusterrolebinding psp-binding --clusterrole=psp:vmxnet3 --serviceaccount=default:psp-sa
```


### Использование сетевых политик


```
kubectl apply -f networkpolicy.yml
```

### Включить ведение журнала аудита

```
kubectl apply -f audit-policy.yaml <br> kubectl edit cm/kube-apiserver -n kube-system <br> Update --audit-log-path and --audit-policy-file
```

### Используйте безопасные конечные точки обслуживания	


```
kubectl patch svc <svc-name> -p '{"spec": {"publishNotReadyAddresses": true, "sessionAffinity": "ClientIP"}}'
```


### Используйте Pod Security Context



`kubectl create sa pod-sa` <br> `kubectl create rolebinding pod-sa --role=psp:vmxnet3 --serviceaccount=default:pod-sa`



### Используйте секреты Kubernetes	

```
kubectl create secret generic <name> --from-file=<path-to-file>
```



### Включить защиту во время выполнения контейнера	

```
kubectl apply -f falco.yaml
```



### Включить контроллеры допуска	


`kubectl edit cm/kube-apiserver -n kube-system` <br> Обновите `--enable-admission-plugins`



