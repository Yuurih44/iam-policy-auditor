# IAM Policy Auditor

Uma ferramenta de linha de comando, escrita em Python, que analisa arquivos JSON de políticas AWS IAM e aponta alguns padrões comuns de permissões arriscadas. O projeto foi pensado para praticar Python, segurança em nuvem e automação com testes.

> A análise é estática e educativa. Ela não reproduz a avaliação de políticas da AWS, não confirma que uma política é segura e não substitui revisão humana ou o IAM Access Analyzer.

## O que verifica

| Regra | Severidade | Padrão encontrado |
| --- | --- | --- |
| IAM001 | Crítica | `Action: "*"` junto de `Resource: "*"` em uma declaração `Allow` |
| IAM002 | Alta | Todas as ações permitidas (`Action: "*"`) |
| IAM003 | Média | Todas as ações de um serviço permitidas, como `s3:*` |
| IAM004 | Alta | A permissão se aplica a qualquer recurso (`Resource: "*"`) |
| IAM005 | Crítica/alta | `Principal: "*"`; uma condição reduz a severidade, mas ainda exige revisão |
| IAM006 | Alta | Ações selecionadas de gerenciamento de permissões IAM |

As regras são intencionalmente pequenas e explicáveis. O auditor não interpreta curingas parciais, condições complexas, políticas de identidade versus políticas de recurso ou a interação entre múltiplas políticas.

## Requisitos

- Python 3.10 ou superior
- Nenhuma dependência de execução externa

## Executar

Clone o repositório e, a partir da pasta do projeto, execute:

```bash
python -m iam_auditor examples/overly-permissive-policy.json
```

Para receber saída JSON, útil em scripts:

```bash
python -m iam_auditor examples/overly-permissive-policy.json --format json
```

Com `--strict`, o programa retorna código `1` quando encontrar achados (e `0` quando não encontrar). Arquivo ausente, JSON inválido ou documento malformado retorna `2`.

Após instalar o projeto em modo editável, também é possível usar o comando `iam-audit`:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
iam-audit examples/least-privilege-policy.json
```

## Testes

```bash
python -m unittest discover -s tests -v
```

Os testes cobrem as regras de auditoria, formatos de `Statement`, saída JSON, modo estrito e tratamento de arquivo ausente.

## Estrutura

```text
iam-policy-auditor/
├── .github/workflows/tests.yml
├── examples/                 # políticas fictícias para demonstração
├── iam_auditor/               # regras e interface de linha de comando
├── tests/                     # testes automatizados com unittest
├── LICENSE
├── pyproject.toml
└── README.md
```

## Uso responsável

Os arquivos em `examples/` são exemplos fictícios e não devem ser usados como políticas reais. Revise qualquer sugestão antes de alterar permissões em uma conta. A ferramenta funciona localmente e não solicita nem utiliza credenciais AWS.

## Licença

Distribuído sob a licença MIT. Consulte [LICENSE](LICENSE).
