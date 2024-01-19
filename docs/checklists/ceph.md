---
layout: default
title: Ceph
parent: Checklists
---

# Усиление Ceph для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Ceph для DevSecOps


### Обновите Ceph до последней версии	 

```
sudo apt-get update && sudo apt-get upgrade ceph -y
```

### Включите шифрование SSL/TLS для трафика Ceph 

```
ceph config set global network.ssl true
```

### Установка безопасных разрешений для файлов конфигурации Ceph 

```
sudo chmod 600 /etc/ceph/*
```

### Ограничение доступа к панели управления Ceph 

```
sudo ufw allow 8443/tcp && sudo ufw allow 8003/tcp && sudo ufw allow 8080/tcp
```

### Настройте Ceph на использование правил брандмауэра 

```
sudo ceph config set global security firewall iptables
```

### Реализуйте сегментацию сети для узлов Ceph 

```
sudo iptables -A INPUT -s <trusted network> -j ACCEPT
```

### Настройка Ceph для использования зашифрованных OSD 

```
sudo ceph-osd --mkfs --osd-uuid <osd-uuid> --cluster ceph --osd-data <path to data directory> --osd-journal <path to journal directory> --osd-encrypted
```

### Используйте SELinux или AppArmor для ограничения процессов Ceph 

`sudo setenforce 1` (для SELinux) или `sudo aa-enforce /etc/apparmor.d/usr.bin.ceph-osd` (для AppArmor) 
