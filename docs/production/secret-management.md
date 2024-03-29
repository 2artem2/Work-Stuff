---
layout: default
title: Secret Management
parent: Production
---

{: .no_toc}

## Оглавление

{: .no_toc .text-delta}

1. TOC

{: toc}

---

# Управление секретами

{: .no_toc}

Управление секретами относится к процессу надежного хранения, управления и доступа к конфиденциальной информации, такой как пароли, ключи API и другие учетные данные.
Секреты являются критически важным компонентом современных приложений, и их безопасное управление имеет важное значение для обеспечения безопасности и целостности приложения.

Управление секретами обычно включает в себя использование специализированных инструментов и технологий, которые обеспечивают безопасное и централизованное место для хранения и управления секретами.
Эти инструменты часто используют прочные механизмы шифрования и контроля доступа для защиты конфиденциальной информации от несанкционированного доступа.

Некоторые из ключевых функций секретных инструментов управления включают в себя:

1. Безопасное хранилище: Секретные инструменты управления предоставляют безопасное место для хранения конфиденциальной информации, обычно используя прочные механизмы шифрования и контроля доступа, чтобы гарантировать, что только авторизованные пользователи могут получить доступ к информации.
2. Контроль доступа: Секретные инструменты управления позволяют администраторам определять политики контроля доступа и роли, которые управляют, кто может получить доступ к конкретным секретам и какие действия они могут выполнить.
3. Аудит и мониторинг: инструменты секретного управления предоставляют возможности для аудита и мониторинга, которые позволяют администраторам отслеживать, кто доступ к конкретным секретам и когда, предоставляя аудиторский след для целей соблюдения и безопасности.
4. Интеграция с другими инструментами: инструменты секретного управления могут быть интегрированы с другими инструментами DevOps, такими как серверы сборки, инструменты развертывания и фреймворки оркестровки, чтобы обеспечить плавный доступ к секретам во время жизненного цикла приложения.

## hashicorp Vault

Высоко безопасное и масштабируемое секретное решение управления, которое поддерживает широкий спектр методов аутентификации и бэкэндов хранения.

```
vault kv put secret/myapp/config username="admin" password="s3cret" API_key="123456789"
```

## Менеджер Secrets AWS

Полностью управляемый сервис управления секретами, предоставленный Amazon Web Services.

```
aws secretsmanager create-secret --name myapp/database --secret-string '{"username":"admin","password":"s3cret"}'
```

## azure Key Vault

Облачная служба управления секретами, предоставляемая Microsoft Azure.

```
az keyvault secret set --name myapp/config --value s3cret
```

## git-crypt

Инструмент командной строки, который позволяет зашифровать файлы и каталоги в репозитории GIT.

```
git-crypt init && git-crypt add-gpg-user user@example.com
```

## Черный ящик

Инструмент командной строки, который позволяет хранить и управлять секретами в репозиториях GIT, используя шифрование GPG.

```
blackbox_initialize && blackbox_register_new_file secrets.txt
```
