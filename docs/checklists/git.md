---
layout: default
title: Git
parent: Checklists
---

# Усиление Git для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Git для DevSecOps


### Включить проверку подписи GPG		

```
git config --global commit.gpgsign true
```


### Задайте надежную парольную фразу для ключа GPG	

```
gpg --edit-key <KEY_ID> а затем используйте команду passwd для установки надежной парольной фразы
```


### Use HTTPS instead of SSH for remote repositories


```
git config --global url."https://".insteadOf git://
```


### Включите двухфакторную аутентификацию	

Включите его на веб-сайте поставщика услуг Git.


### Настройте Git на игнорирование изменений режима файла


```
git config --global core.fileMode false
```

### Настройте Git на использование помощника учетных данных

`git config --global credential.helper <helper>` где `<helper>` имя помощника по работе с учетными данными (например, `manager`, `store`)


### Используйте подписанные коммиты

```
git commit -S
```
 или 

```
 git config --global commit.gpgsign true
```



### Настройте Git на автоматическую обрезку устаревших веток с удаленным отслеживанием

```
git config --global fetch.prune true
```


### Настройте Git так, чтобы при вытягивании всегда выполнялся rebase, а не merge


```
git config --global pull.rebase true
```


### Используйте функцию Git'а `ignore` для исключения чувствительных файлов	



Добавление файлов или шаблонов файлов в файл `.gitignore`.







