# 🏛️ GCL - Gerenciamento de Conformidade Legal

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange.svg)](https://aws.amazon.com/lambda/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Descrição

O **GCL (Gerenciamento de Conformidade Legal)** é uma solução automatizada para monitoramento de conformidade legal que executa na AWS Lambda. Este sistema realiza verificações periódicas em fontes legais, monitora mudanças em regulamentações e mantém um registro atualizado de conformidade.

## 🚀 Funcionalidades

- ✅ **Monitoramento Automatizado**: Verifica alterações em documentos legais e regulamentações
- 📊 **Análise de Documentos**: Processa PDFs e páginas web para extrair informações relevantes
- 🔄 **Verificação Periódica**: Execução programada para manter dados sempre atualizados
- 💾 **Armazenamento Seguro**: Integração com DynamoDB para persistência de dados
- 📧 **Notificações**: Sistema de alertas para mudanças importantes
- 🛡️ **Tratamento de Erros**: Robustez na manipulação de falhas de rede e timeouts

## 🏗️ Arquitetura

### Componentes Principais

- **AWS Lambda**: Função serverless para processamento
- **DynamoDB**: Banco de dados NoSQL para armazenamento
- **CloudWatch**: Monitoramento e logs
- **EventBridge**: Agendamento de execuções

### Dependências

- `boto3`: SDK da AWS para Python
- `requests`: Requisições HTTP
- `BeautifulSoup4`: Parse de HTML
- `PyPDF2`: Processamento de PDFs
- `urllib3`: Utilitários de HTTP

## ⚙️ Configuração

### Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `AWS_REGION` | `us-east-2` | Região AWS para recursos |
| `TABELA` | `Monitoramento_Conformidade_Legal` | Nome da tabela DynamoDB |
| `MAX_WORKERS` | `8` | Número máximo de workers paralelos |
| `REQUEST_TIMEOUT` | `25` | Timeout para requisições HTTP (segundos) |
| `LOG_LEVEL` | `INFO` | Nível de logging (DEBUG, INFO, WARNING, ERROR) |
| `ENABLE_HEAD_CHECK` | `false` | Habilita verificação HEAD antes do GET |
| `VERBOSE` | `false` | Modo verboso para debugging |
| `DISABLE_SSL_VERIFY` | `false` | Desabilita verificação SSL (não recomendado para produção) |

## 📦 Instalação

### Pré-requisitos

- Python 3.8+
- AWS CLI configurado
- Conta AWS com permissões apropriadas

### Deploy na AWS Lambda

1. **Clone o repositório**:
   ```bash
   git clone https://github.com/EnzoQualy/GCL---Gerenciamento-de-Conformidade-Legal.git
   cd GCL---Gerenciamento-de-Conformidade-Legal
   ```

2. **Crie o pacote de deployment**:
   ```bash
   zip -r monitoramento-conformidade.zip .
   ```

3. **Crie a função Lambda**:
   ```bash
   aws lambda create-function \
     --function-name MonitoramentoConformidadeLegal \
     --runtime python3.9 \
     --role arn:aws:iam::YOUR_ACCOUNT:role/lambda-execution-role \
     --handler lambda_function.lambda_handler \
     --zip-file fileb://monitoramento-conformidade.zip
   ```

4. **Configure as variáveis de ambiente**:
   ```bash
   aws lambda update-function-configuration \
     --function-name MonitoramentoConformidadeLegal \
     --environment Variables='{TABELA=Monitoramento_Conformidade_Legal,LOG_LEVEL=INFO}'
   ```

### Infraestrutura AWS Necessária

#### DynamoDB Table
```bash
aws dynamodb create-table \
  --table-name Monitoramento_Conformidade_Legal \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

#### IAM Role Permissions
A função Lambda precisa das seguintes permissões:
- `dynamodb:PutItem`
- `dynamodb:GetItem`
- `dynamodb:UpdateItem`
- `dynamodb:Scan`
- `logs:CreateLogGroup`
- `logs:CreateLogStream`
- `logs:PutLogEvents`

## 🔧 Uso

### Execução Manual
```python
import json
from lambda_function import lambda_handler

# Evento de exemplo
event = {
    "action": "monitor",
    "sources": ["https://example.com/legal-doc.pdf"]
}

response = lambda_handler(event, None)
print(json.dumps(response, indent=2))
```

### Agendamento Automático
Configure um EventBridge Rule para execução periódica:
```bash
aws events put-rule \
  --name MonitoramentoConformidadeSchedule \
  --schedule-expression "rate(24 hours)"

aws events put-targets \
  --rule MonitoramentoConformidadeSchedule \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-2:ACCOUNT:function:MonitoramentoConformidadeLegal"
```

## 📊 Monitoramento

### CloudWatch Logs
- Logs detalhados de execução
- Métricas de performance
- Alertas automáticos para erros

### Métricas Importantes
- Taxa de sucesso de verificações
- Tempo de execução
- Número de documentos processados
- Erros de rede/timeout

## 🛠️ Desenvolvimento

### Estrutura do Projeto
```
├── lambda_function.py      # Função principal
├── requirements.txt        # Dependências Python
├── README.md              # Esta documentação
├── boto3/                 # SDK AWS
├── botocore/             # Core do boto3
├── bs4/                  # BeautifulSoup
├── PyPDF2/               # Processador de PDF
├── requests/             # HTTP requests
└── outros módulos...
```

### Executar Localmente
```bash
# Instalar dependências
pip install -r requirements.txt

# Configurar variáveis de ambiente
export AWS_REGION=us-east-2
export TABELA=Monitoramento_Conformidade_Legal

# Executar testes
python -m pytest tests/
```

## 🤝 Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

## 📝 Changelog

### [2025-08-27-R1]
- Versão inicial do sistema
- Implementação do monitoramento básico
- Integração com DynamoDB
- Processamento de PDFs e páginas web
- Sistema de logging configurável

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👨‍💻 Autor

**Enzo Qualy** - [EnzoQualy](https://github.com/EnzoQualy)

## 📞 Suporte

Para suporte, abra uma issue no GitHub ou entre em contato:
- Email: enzo.oliveira@mindworks.com.br
- GitHub: [@EnzoQualy](https://github.com/EnzoQualy)

---

⭐ **Se este projeto foi útil para você, considere dar uma estrela no GitHub!**