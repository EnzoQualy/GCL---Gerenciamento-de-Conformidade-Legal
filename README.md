# GCL---Gerenciamento-de-Conformidade-Legal

**Versão:** 2025-08-27-R1

## Descrição

Este projeto realiza o monitoramento automatizado de fontes legais (ex: portais, documentos PDF, páginas HTML) para detectar mudanças em conteúdo relevante. O sistema armazena metadados e resultados em uma tabela DynamoDB, envia notificações detalhadas via SNS (Amazon Simple Notification Service) e provê logs estruturados para auditoria.

O principal objetivo é garantir que alterações relevantes em documentos legais sejam rapidamente identificadas e reportadas, facilitando a conformidade normativa e o acompanhamento de legislações, atos oficiais ou publicações jurídicas.

---

## Principais Funcionalidades

- **Monitoramento de URLs:** Suporte a páginas HTML e documentos PDF externos, com reconhecimento automático do tipo de conteúdo.
- **Processamento Paralelo:** Utiliza múltiplos workers para acelerar o processamento das fontes monitoradas.
- **Detecção de Mudanças:** Compara hashes e contagem de caracteres para identificar alterações significativas ou pequenas.
- **Notificações Automatizadas:** Gera resumos e estatísticas sobre mudanças e erros, enviando notificações via SNS.
- **Persistência de Dados:** Utiliza DynamoDB para armazenar o estado de monitoramento, incluindo última hash, data de última verificação, e metadados.
- **Configuração Flexível:** Parâmetros ajustáveis via variáveis de ambiente (ex: número de workers, limites de tamanho, controle de SSL, tópicos SNS, etc).
- **Logs detalhados:** Logging configurável, com diferentes níveis de verbosidade e auditoria das execuções.

---

## Estrutura do Código

- **Funções utilitárias:** Manipulação de texto, hash, extração de conteúdo HTML/PDF, normalização de dados.
- **Processamento principal:** `main_run()` executa o monitoramento de todas as fontes cadastradas, podendo rodar em paralelo.
- **Notificações:** Geração e envio de mensagens detalhadas sobre mudanças e erros detectados.
- **Persistência:** Atualizações e leituras na tabela DynamoDB (`Monitoramento_Conformidade_Legal` por padrão).
- **Handler Lambda:** Função `lambda_handler` pronta para execução em ambiente AWS Lambda.
- **Execução local:** Suporte a rodar o monitoramento e notificações de forma local para testes/desenvolvimento.

---

## Principais Variáveis de Ambiente

| Variável                | Descrição                                                      | Valor padrão               |
|-------------------------|---------------------------------------------------------------|----------------------------|
| `AWS_REGION`            | Região AWS utilizada (ex: us-east-2)                          | us-east-2                  |
| `TABELA`                | Nome da tabela DynamoDB                                       | Monitoramento_Conformidade_Legal |
| `MAX_WORKERS`           | Número de workers paralelos                                   | 8                          |
| `REQUEST_TIMEOUT`       | Timeout de requisições HTTP (segundos)                        | 25                         |
| `LOG_LEVEL`             | Nível de log (ex: INFO, DEBUG, WARNING)                       | INFO                       |
| `ENABLE_HEAD_CHECK`     | Habilita checagem via HEAD antes de baixar conteúdo           | false                      |
| `VERBOSE`               | Habilita logs detalhados                                      | false                      |
| `DISABLE_SSL_VERIFY`    | Desabilita verificação SSL (apenas para debug!)               | false                      |
| `MAX_CONTENT_BYTES`     | Tamanho máximo permitido do conteúdo baixado (bytes)          | 5 MB (5 * 1024 * 1024)     |
| `USER_AGENT`            | User-Agent customizado para requisições                       | LegalMonitorBot/1.1        |
| `SNS_TOPIC_ARN`         | ARN do tópico SNS para notificações                           | (padrão ou definido)       |
| `MIN_NOTIFY_DELTA`      | Variação mínima de caracteres para destacar mudança crítica    | 50                         |
| `NOTIFY_ERRORS`         | Envia detalhes de erros nas notificações                      | false                      |
| `INCLUDE_OK_CHANGES`    | Sempre lista mudanças, mesmo pequenas                         | true                       |
| `MAX_LIST_CHANGES`      | Número máximo de mudanças listadas nas notificações           | 30                         |
| `MAX_LIST_ERRORS`       | Número máximo de erros listados nas notificações              | 30                         |

---

## Principais Dependências

- **boto3:** Cliente AWS SDK para Python (DynamoDB e SNS)
- **requests:** HTTP client para download de conteúdos e checagem de HEAD
- **BeautifulSoup4:** Extração de texto de HTML
- **PyPDF2:** Extração de texto de arquivos PDF
- **urllib3:** Geração de alertas e controle de warnings SSL
- **logging:** Logging estruturado
- **concurrent.futures:** Multiprocessamento via ThreadPoolExecutor

---

## Como funciona o Monitoramento

1. **Coleta dos Itens:** Todos os itens cadastrados na tabela DynamoDB são lidos.
2. **Processamento dos Itens:** Cada fonte é processada individualmente; o conteúdo é baixado e seu texto extraído.
3. **Cálculo de Hash e Delta:** O texto extraído gera um hash SHA256 e é comparado com o estado anterior.
4. **Detecção de Mudança:** Se detectada alteração, o item é atualizado na tabela e registrado como alterado.
5. **Notificação:** Ao final do processamento, um resumo detalhado é enviado via SNS.
6. **Logs:** Toda execução é registrada por meio de logs para auditoria e troubleshooting.

---

## Notificações

As notificações incluem:

- Resumo geral da execução
- Distribuição dos status dos itens
- Mudanças críticas (com variação significativa)
- Lista de todas as mudanças detectadas
- Detalhes de erros, caso habilitado

As notificações são enviadas ao tópico SNS configurado (`SNS_TOPIC_ARN`).

---

## Execução

### AWS Lambda

A principal função de entrada é `lambda_handler(event, context)`, que pode ser configurada como handler em uma função Lambda.

### Local

O arquivo pode ser executado diretamente via linha de comando para testes locais:

```sh
python nome_do_arquivo.py
```

---

## Personalização & Extensão

- Para adicionar novas fontes, insira registros na tabela DynamoDB com os campos esperados (`Codigo`, `Nome`, `Fonte`, etc.).
- Parâmetros de execução podem ser ajustados via variáveis de ambiente.
- O processamento pode ser extendido para novos tipos de arquivos implementando novas funções de extração.
- Integração com outros sistemas de notificação pode ser implementada a partir das funções de envio.

---

## Considerações de Segurança

- **ATENÇÃO**: A opção `DISABLE_SSL_VERIFY=true` desabilita verificação de certificados SSL e só deve ser usada em ambientes de desenvolvimento.
- O projeto utiliza IAM roles/credenciais AWS para acesso a DynamoDB e SNS.
- Audite o controle de acesso à tabela e ao tópico SNS conforme boas práticas AWS.

---

## Exemplos de Campos na Tabela DynamoDB

```json
{
  "Codigo": {"S": "LEI123"},
  "Nome": {"S": "Lei Municipal 123"},
  "Fonte": {"S": "https://www.prefeitura.gov.br/leis/lei123.pdf"},
  "Status": {"S": "vigente"},
  "LastHash": {"S": "..."},
  "LastCharCount": {"N": "12345"},
  "LastChangeAt": {"S": "2025-08-27T14:00:00Z"},
  "ContentType": {"S": "application/pdf"}
}
```

---

## Contato & Suporte

Para dúvidas, sugestões ou contribuições, entre em contato com o mantenedor do projeto.

---

## Licença

Este projeto é distribuído sob licença MIT (ou conforme definido pelo mantenedor).
