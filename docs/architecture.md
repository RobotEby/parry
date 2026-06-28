# Parry_DDoS — Decisões de Arquitetura

## Estrutura de diretórios

```
ParryWAF/
├── src/
│   ├── detectors/          Detectores de ameaça (SQL, XSS, NoSQL)
│   ├── express/            Adapter Express: req/res/next, IP, targets
│   ├── middleware/         Ponto de entrada público compatível
│   ├── core/               Engine, eventos e scoring
│   ├── rate-limit/         RateLimiter baseado em Store
│   ├── policies/           Match e normalização de policies por rota
│   ├── brute-force/        BruteForceGuard e key builder de autenticação
│   ├── stores/             Contrato Store, MemoryStore e RedisStore
│   └── logger/             Reporter de console
├── config/                 Valores padrão configuráveis
├── constants/              Padrões regex centralizados
├── types/                  Tipagem pública TypeScript
├── tests/
│   ├── unit/               Um arquivo por módulo
│   ├── integration/        Middleware testado end-to-end com req/res mock
│   └── fixtures/           Payloads de ataque compartilhados
├── examples/               Demonstrações (fora de src/)
└── docs/                   Documentação de arquitetura e decisões
```

---

## Por que `core/` é separado de `middleware/`?

O código que conhece `req`, `res` e `next` fica em `src/express/`. O engine recebe
dados normalizados e não depende do protocolo HTTP. `RateLimiter`, stores e logger
são utilitários independentes, o que permite testes unitários isolados e uso futuro
em outros adapters.

## Por que `constants/patterns.js` existe?

Centralizar todos os regex em um único arquivo resolve três problemas:

1. **Manutenção** — ajustar um padrão não requer abrir o detector correspondente.
2. **Revisão de segurança** — um revisor encontra todos os padrões num só lugar.
3. **Testes** — os fixtures de `tests/fixtures/payloads.js` são derivados dos mesmos
   padrões, garantindo que testes e detectores estejam sempre alinhados.

## Por que `config/defaults.js` e não constantes inline?

Permite que integradores inspecionem os defaults sem ler o código do middleware.
Facilita também testes que precisam sobrescrever apenas um subconjunto de opções.

## Por que `tests/` fica na raiz e não dentro de `src/`?

Testes não são código de produção. Incluí-los em `src/` os tornaria parte do bundle
publicado e obscureceria a separação entre código executável e código de verificação.

## Estratégia de detecção em camadas

Cada detector aplica decodificação antes de escanear:

```
input → URL decode (multi-pass) → HTML entity decode → Unicode strip → scan
```

Isso cobre os vetores de bypass mais comuns (double encoding, zero-width chars,
entity injection) sem depender de bibliotecas externas.

## Rate Limiting inteligente

O `RateLimiter` mantém dois contadores separados por IP através de uma Store:

- **rate limit** — contador de requisições da janela ativa.
- **`suspicious`** — incrementado a cada ameaça detectada, independente da janela.

O banimento é acionado pelo `suspicious`, não pelo volume. Isso permite que um IP
legítimo com alto volume não seja banido, enquanto um IP com poucas requisições
mas todas maliciosas seja bloqueado rapidamente.

## Policies por rota e brute force

Policies são avaliadas no adapter Express, antes do engine principal, porque
dependem de `method`, `path`, `req`, `res` e do status final da resposta.

- O matcher suporta method/path exatos, arrays, wildcard simples e `RegExp`.
- O route rate limit usa counters genéricos da Store com namespace separado.
- O `BruteForceGuard` verifica bloqueios antes da rota e usa `res.on('finish')`
  para registrar falhas ou sucessos de autenticação depois que o handler decide
  o status final.
- `req.parry.recordAuthFailure()` e `req.parry.recordAuthSuccess()` permitem que
  handlers que respondem `200` com `{ success: false }` controlem o resultado
  manualmente sem dupla contagem.

## Considerações de produção

- `MemoryStore` é o padrão e protege apenas o processo atual. Para múltiplas
  instâncias (clusters, Kubernetes, containers ou load balancers), use `RedisStore`
  ou outra Store compartilhada.
- `RedisStore` recebe um client Redis externo. O pacote não adiciona Redis como
  dependência obrigatória.
- Chaves de brute force não devem incluir senha, tokens, cookies ou headers de
  autorização. O key builder padrão bloqueia caminhos sensíveis como
  `body.password`.
- O `x-forwarded-for` não é verificado contra uma lista de proxies confiáveis.
  Em produção, adicione verificação de CIDR antes de confiar nesse header.
- Os padrões regex cobrem os vetores mais comuns mas não são exaustivos.
  Considere complementar com uma WAF dedicada em camadas de alta criticidade.
