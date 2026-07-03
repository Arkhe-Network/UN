# ADR-001: Integração DeSciOS como Crate `arkhe-desci`

**Status:** Aprovado
**Data:** 2026-07-01
**Decisores:** Arquiteto-Chefe (IC6), ITSec, DPO

## Contexto

O DeSciOS é um ambiente containerizado para ciência descentralizada com:
- Docker + noVNC + XFCE4
- Suíte científica (Jupyter, RStudio, QGIS, UGENE, Nextflow)
- Assistente IA local (Ollama)
- IPFS + Syncthing + FunDeSci

**Problemas identificados:** 23 vulnerabilidades (CWE mapeadas), falta de governança de plugins, sem PII masking, sem rastreabilidade de workflows.

## Decisão

**Criar crate `arkhe-desci`** no monorepo ARKHE, com integração condicionada à correção das vulnerabilidades críticas no DeSciOS.

### Arquitetura Proposta

```
┌─────────────────────────────────────────────┐
│  ARKHE MONOREPO                             │
│  ┌───────────────────────────────────────┐  │
│  │  arkhe-desci crate                     │  │
│  │  ├── PluginValidator                  │  │
│  │  ├── AssistantGuardrails              │  │
│  │  ├── WorkflowTraceability (IC16)      │  │
│  │  └── DeSciPublisher (IPFS+CCIP)      │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│  DeSciOS (containerizado)                    │
│  • Dockerfile corrigido (CWE-798, etc.)     │
│  • Launcher com sanitização                 │
│  • Assistant com guardrails                 │
└─────────────────────────────────────────────┘
```

## Consequências

**Positivas:**
- Segurança do DeSciOS melhorada (23 vulnerabilidades corrigidas)
- Rastreabilidade de workflows via IC16
- Reutilização de invariantes ARKHE (OWASP-003, CNT-002, OWASP-006)

**Negativas:**
- Exige correção prévia do DeSciOS (6-8 semanas)
- Dependência de crates externos (`reqwest`, `blake3`)

## Riscos e Mitigações

| Risco | Mitigação |
|-------|-----------|
| Vulns não corrigidas | Condição de merge: todas as críticas resolvidas |
| Breaking changes externas | Features opcionais (`ipfs`, `chainlink`) |
| Complexidade de integração | Testes unitários + E2E com mock |

## Plano de Implementação

| Fase | Período | Entregável |
|------|---------|------------|
| 1 | Semana 1-2 | Corrigir 7 vulns críticas no DeSciOS |
| 2 | Semana 3-4 | Criar crate `arkhe-desci` com estrutura |
| 3 | Semana 5-6 | Integrar e testar end-to-end |
| 4 | Semana 7-8 | Documentação final |

## Status

**Aprovado** — Aguardando correções do DeSciOS.
