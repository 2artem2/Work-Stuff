---
layout: default
title: CloudFormation
parent: Rules
---

# CloudFormation
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### Строго закодированное имя

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
# Несоответствующий код
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
```

В этом коде, не соответствующем требованиям, шаблон AWS CloudFormation используется для создания ведра S3. Имя ведра жестко закодировано как my-bucket без учета возможных конфликтов имен или лучших практик безопасности. Такой подход создает риски для безопасности, поскольку имя ведра может быть уже занято или в нем может быть случайно раскрыта конфиденциальная информация.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
# Compliant code
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: 
        Fn::Sub: "my-bucket-${AWS::StackName}-${AWS::Region}"
]
```


В соответствующем коде имя ведра генерируется динамически с помощью внутренней функции Fn::Sub. Имя ведра состоит из строки "my-bucket-", за которой следует имя текущего стека CloudFormation (AWS::StackName) и регион AWS (AWS::Region). Такой подход обеспечивает уникальность имени ведра в пределах стека CloudFormation и помогает смягчить потенциальные конфликты имен.

Используя динамическое именование с помощью функции Fn::Sub, вы можете избежать жестко заданных значений и обеспечить более гибкий и безопасный подход к созданию ресурсов в CloudFormation.

Кроме того, вы можете реализовать другие меры безопасности, такие как:

* Использование политик IAM для контроля разрешений доступа к созданным ресурсам.
* Реализация разрешений на уровне ресурсов с помощью ролей и политик AWS Identity and Access Management (IAM).
* Шифрование конфиденциальных данных в состоянии покоя с помощью AWS Key Management Service (KMS) или других механизмов шифрования.
* Реализация политик стека CloudFormation на уровне стека или ресурсов для контроля обновлений стека и предотвращения несанкционированных изменений.

Следуя лучшим практикам безопасности и используя динамические значения в шаблонах CloudFormation, вы сможете повысить безопасность, гибкость и надежность развертывания инфраструктуры в AWS.




Semgrep:


```
rules:
  - id: noncompliant-s3-bucket-properties
    patterns:
      - pattern: 'Type: AWS::S3::Bucket\n    Properties:\n      BucketName: .+'
    message: "Noncompliant S3 bucket properties"
```

CodeQL:



```
import cf

from Template t
where exists (Bucket b | b.getType().toString() = "AWS::S3::Bucket")
  and not exists (Bucket b | b.getType().toString() = "AWS::S3::Bucket" and b.getProperties().get("BucketName") != null)
select t
```



