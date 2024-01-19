---
layout: default
title: eBPF
parent: Checklists
---

# Контрольный список безопасности eBPF для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик eBPF для DevSecOps




### Включить упрочнение eBPF 

```
echo 1 > /proc/sys/net/core/bpf_jit_harden
```


### Ограничение загрузки программы eBPF 

```
setcap cap_bpf=e /path/to/program
```

### Ограничить доступ к точкам трассировки eBPF      

```
echo 0 > /proc/sys/kernel/perf_event_paranoid
```


### Используйте eBPF для мониторинга системных вызовов 

```
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
```

### Включите мониторинг безопасности на основе eBPF    

```
bpftool prog load secmon.bpf /sys/fs/bpf/
```

### Ограничение операций с картой eBPF 

```
bpftool map create /sys/fs/bpf/my_map type hash key 4 value 4 entries 1024
```

### Регулярно обновляйте инструменты и библиотеки eBPF

```
apt-get update && apt-get upgrade libbpf-tools
```
