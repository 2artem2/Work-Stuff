---
layout: default
title: SBOM
parent: Checklists
---

# Контрольный список безопасности SBOM для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик SBOM для DevSecOps




### Создание SBOM для вашего программного обеспечения

```
cyclonedx-bom -o sbom.xml
```


### Проверка сгенерированного SBOM   

```
bom-validator sbom.xml
```

### Интеграция генерации SBOM в пайплайн CI/CD              


Добавьте шаг генерации SBOM в сценарий CI/CD



### Регулярное обновление инструментов SBOM 

```
apt-get update && apt-get upgrade cyclonedx-bom
```

### Обзор и анализ SBOM на предмет уязвимостей

```
sbom-analyzer sbom.xml
```

### Убедитесь, что SBOM является всеобъемлющим и включает все компоненты


Обзор SBOM и добавление недостающих компонентов


### Защита данных SBOM с помощью надлежащих средств контроля доступа  


Настройка контроля доступа к данным SBOM



### Мониторинг и обновление SBOM для каждого выпуска      


Автоматическое обновление SBOM для каждого выпуска


