---
layout: default
title: Azure
parent: MlSecOps
---


# Azure 
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Принципы ответственного искусственного интеллекта



- [ ] Машинное обучение в Azure

Azure Machine Learning - это облачная служба для создания, обучения и развертывания моделей машинного обучения. Она предоставляет инструменты и возможности для поддержки ответственных практик в области искусственного интеллекта.

```
az ml workspace create --workspace-name <workspace-name> --resource-group <resource-group> --location <location>
```




- [ ] Интерпретируемость машинного обучения Azure

Azure Machine Learning Interpretability предоставляет инструменты для понимания и интерпретации моделей машинного обучения, делая их более прозрачными и понятными.

```
azureml-interpret
```





- [ ] Когнитивные службы Azure

Службы Azure Cognitive Services предлагают готовые модели ИИ и API для таких задач, как обработка естественного языка, компьютерное зрение и распознавание речи. Эти службы можно использовать ответственно, соблюдая рекомендации и учитывая соображения справедливости и предвзятости.

```
az cognitiveservices account create --name <service-name> --resource-group <resource-group> --kind TextAnalytics --sku <sku-name> --location <location>
```




- [ ] Этика и управление ИИ в Azure

Azure предоставляет различные инструменты и функции управления для обеспечения ответственного подхода к ИИ, включая Azure Policy, Azure Blueprints и Azure Advisor.



