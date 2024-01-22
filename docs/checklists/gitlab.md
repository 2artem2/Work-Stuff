---
layout: default
title: Gitlab
parent: Checklists
---

# Усиление Gitlab для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Gitlab для DevSecOps


### Обновите GitLab до последней версии	


```
sudo apt-get update && sudo apt-get upgrade gitlab-ee
```


### Включите SSL/TLS для GitLab	


Edit /etc/gitlab/gitlab.rb и добавьте следующие строки: <br>external_url 'https://gitlab.example.com'<br>nginx['redirect_http_to_https'] = true<br>nginx['ssl_certificate'] = "/etc/gitlab/ssl/gitlab.example.com.crt"<br>nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/gitlab.example.com.key"<br>gitlab_rails['gitlab_https'] = true<br>gitlab_rails['trusted_proxies'] = ['192.168.1.1'] (замените 192.168.1.1 на IP-адрес вашего прокси-сервера) <br> Затем выполните команду sudo gitlab-ctl reconfigure



### Отключить регистрацию в GitLab	

Редактируйте /etc/gitlab/gitlab.rb и добавьте следующую строку:<br>gitlab_rails['gitlab_signup_enabled'] = false <br> Затем выполните команду sudo gitlab-ctl reconfigure



### Установите строгую политику паролей


Редактируйте /etc/gitlab/gitlab.rb и добавьте следующие строки: <br>gitlab_rails['password_minimum_length'] = 12<br>gitlab_rails['password_complexity'] = 2<br> Затем выполните команду sudo gitlab-ctl reconfigure


### Ограничение максимального размера файла

Редактируйте /etc/gitlab/gitlab.rb и добавьте следующую строку:<br>gitlab_rails['max_attachment_size'] = 10.megabytes <br> Затем выполните команду sudo gitlab-ctl reconfigure


### Включите двухфакторную аутентификацию (2FA)

Зайдите в веб-интерфейс GitLab, нажмите на изображение своего профиля в правом верхнем углу и выберите "Настройки". Затем в левом меню выберите "Учетная запись" и следуйте подсказкам, чтобы настроить 2FA.



### Включите ведение журнала аудита	

Редактируйте /etc/gitlab/gitlab.rb и добавьте следующую строку:<br>gitlab_rails['audit_events_enabled'] = true<br> Затем выполните команду sudo gitlab-ctl reconfigure



### Настройка резервного копирования GitLab		


Редактируйте /etc/gitlab/gitlab.rb и добавьте следующие строки:<br>gitlab_rails['backup_keep_time'] = 604800<br>gitlab_rails['backup_archive_permissions'] = 0644<br>gitlab_rails['backup_pg_schema'] = 'public'<br>gitlab_rails['backup_path'] = "/var/opt/gitlab/backups"<br> Затем выполните команду sudo gitlab-ctl reconfigure



### Ограничение доступа к SSH


Редактируйте /etc/gitlab/gitlab.rb и добавьте следующую строку:<br>gitlab_rails['gitlab_shell_ssh_port'] = 22<br> Затем выполните команду sudo gitlab-ctl reconfigure


### Включите правила брандмауэра


Настройте свой брандмауэр так, чтобы он разрешал входящий трафик только на порты, необходимые для работы GitLab, например 80, 443 и 22. Обратитесь к документации по брандмауэру за инструкциями по настройке правил брандмауэра.

