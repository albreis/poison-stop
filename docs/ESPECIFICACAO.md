# PoisonStop

> Proxy de saída (egress) com painel para Docker: registra para onde cada serviço manda requisições, sugere a whitelist sozinho e bloqueia o resto.

Status: ideia / especificação do MVP · Data: 2026-11-14 · Autor: Everaldo

---

## 1. Nome

**PoisonStop** ("Parada de Envenenamento"), escrito junto.

- Repositório e imagem: `poison-stop` ([github.com/albreis/poison-stop](https://github.com/albreis/poison-stop), `ghcr.io/albreis/poison-stop`)
- Binário/CLI: `poisonstop`
- Tagline sugerida: *"Your dependencies can read your secrets. They just can't send them anywhere."*
- Variação curta, se precisar: **PStop** (para comandos ou logs).

O nome conversa direto com o problema: pacote envenenado (supply chain) que tenta mandar dados para fora.

---

## 2. Problema e motivação

**O ataque mais comum de hoje não arromba a porta, ele já está dentro.** Um pacote do npm, do Composer ou do PyPI é comprometido (ou um typosquatting é instalado por engano), roda no `postinstall` ou no boot da aplicação, lê variáveis de ambiente, `.env`, tokens do Vault, chaves de cloud, e manda tudo para um servidor do atacante. O mesmo vale para uma RCE numa aplicação Laravel ou num plugin.

O que esses ataques têm em comum é **a saída**. O código malicioso precisa enviar os dados para algum lugar. Se o serviço só consegue falar com os hosts que ele realmente usa, a chave roubada fica presa dentro do container.

Mesmo assim, quase nenhum desenvolvedor monitora o tráfego de saída:

- Docker, por padrão, deixa todo container falar com a internet inteira.
- Firewall de servidor costuma filtrar só a **entrada**.
- Ninguém sabe responder "para quais hosts o meu serviço de pagamento manda requisições?".
- Montar uma allowlist na mão é chato, então ninguém faz.

**Defesa em camadas que o PoisonStop completa:**

| Camada | Protege contra | Exemplo |
|---|---|---|
| IP restrito no token | Uso da chave **fora** da sua infra | Token do Vault/AppRole com `secret_id_bound_cidrs` |
| Escopo mínimo | Estrago se a chave vazar | Chave de API só com leitura |
| Limite de gasto | Abuso financeiro | Quota/budget na cloud |
| **Egress restrito (PoisonStop)** | Código malicioso **dentro** da sua infra mandando a chave para fora | Serviço só fala com `api.stripe.com` |

---

## 3. Alternativas existentes

| Ferramenta | O que faz bem | Por que não resolve para o dev pequeno |
|---|---|---|
| **Cilium + Hubble** | Política por FQDN, observabilidade de rede excelente via eBPF | Exige Kubernetes e conhecimento de rede; overkill para um VPS com Docker Compose |
| **Istio egress gateway** | Controle fino de saída em service mesh | Complexo, pesado, só faz sentido com Istio já rodando |
| **Calico (Enterprise)** | NetworkPolicy com DNS/FQDN | FQDN é recurso pago/enterprise; Kubernetes |
| **Squid com allowlist** | Proxy maduro, filtra por domínio | Configuração em arquivo, sem painel, sem modo aprendizado, sem visão por serviço |
| **StepSecurity Harden-Runner** | Exatamente essa ideia (aprendizado + bloqueio) | Só funciona dentro do GitHub Actions (CI), não em produção |
| **OpenSnitch / Little Snitch** | Firewall de saída com UI | Para desktop, não para containers/servidores |
| **Pi-hole / AdGuard Home** | Bloqueio por DNS com painel | Pensado para rede doméstica; bloqueio só por DNS é fácil de contornar com IP direto |

**O diferencial do PoisonStop:**

1. **Feito para Docker Compose e VPS**, o ambiente real de agência, freelancer e startup pequena.
2. **Modo aprendizado:** observa por alguns dias e **gera a whitelist sozinho**. Ninguém precisa montar lista na mão.
3. **Visão por serviço:** cada container tem sua própria lista, seu histórico e seus alertas.
4. **Um container só, com painel embutido.** Sobe com `docker compose up` em 5 minutos.
5. **Alerta de "host novo"**: a primeira vez que um serviço tenta falar com um destino desconhecido é o melhor sinal de comprometimento que existe.

---

## 4. MVP (versão 0.1)

### 4.1 Modo aprendizado (`learn`)
- Deixa tudo passar, mas **registra** cada conexão: serviço de origem, host de destino, porta, protocolo, bytes, data.
- Depois do período (padrão: 7 dias, configurável), o painel mostra uma **whitelist sugerida por serviço**, com contagem de uso de cada host.
- O usuário revisa, desmarca o que parecer estranho e aprova com um clique.
- Destaque visual para hosts "suspeitos" na sugestão: wildcards largos (`*.googleapis.com`, `*.amazonaws.com`), serviços de paste/upload (`pastebin.com`, `transfer.sh`, `webhook.site`, `ngrok`), IPs diretos sem nome.

### 4.2 Modo bloqueio (`enforce`)
- Por serviço: só passa o que estiver na whitelist, o resto recebe recusa (HTTP 403 no proxy, conexão fechada no CONNECT).
- Modos podem ser misturados: o serviço A em `enforce`, o B ainda em `learn`.
- Modo intermediário `monitor`: deixa passar mas **alerta** quando sai da lista (bom para a transição).

### 4.3 Alertas
- Canais no MVP: **Telegram** e **webhook genérico** (que já cobre n8n, Slack, Discord). E-mail (SMTP) logo em seguida.
- Eventos: conexão bloqueada, host novo visto pela primeira vez, pico de volume para um destino.
- Agrupamento (debounce) para não inundar: no máximo um alerta por serviço+host a cada X minutos.

### 4.4 Painel
- **Visão geral:** serviços, modo de cada um, bloqueios nas últimas 24h.
- **Por serviço:** destinos, volume, primeira e última vez vistos, gráfico simples por hora.
- **Bloqueios:** lista das tentativas negadas, com botão "liberar este host".
- **Whitelist:** editar a lista de cada serviço, importar/exportar YAML.
- Login com usuário e senha (bcrypt), sessão por cookie. Painel **nunca** exposto na rede dos serviços monitorados.

### 4.5 Fora do MVP (de propósito)
- Inspeção do conteúdo HTTPS (MITM). O MVP não abre o tráfego.
- Kubernetes.
- Multiusuário com permissões.

---

## 5. Arquitetura

```
                       internet
                          ▲
                          │ (só o PoisonStop sai)
              ┌───────────┴────────────┐
   rede       │      poisonstop        │  painel :8080 (rede "admin")
  "egress"    │  proxy  │ dns │ painel │
              └───────────┬────────────┘
                          │  rede "apps" (internal: true)
          ┌───────────────┼───────────────┐
      ┌───┴───┐       ┌───┴───┐       ┌───┴───┐
      │  app  │       │worker │       │ mysql │
      └───────┘       └───────┘       └───────┘
```

### 5.1 Isolamento de rede (a base de tudo)
- Os serviços ficam numa rede Docker `internal: true`. **Nessa rede não existe rota para a internet**, então não dá para "pular" o proxy.
- O container `poisonstop` é o único que está nas duas redes: `apps` (interna) e `egress` (com saída).
- Isso garante que a filtragem não depende da boa vontade da aplicação.

Exemplo de `docker-compose.yml`:

```yaml
services:
  poisonstop:
    image: ghcr.io/albreis/poison-stop:latest
    networks: [apps, egress]
    ports: ["127.0.0.1:8080:8080"]   # painel só local / atrás de VPN
    volumes:
      - ./poisonstop-data:/data
      - ./poisonstop.yml:/etc/poisonstop.yml:ro

  app:
    image: minha-app-laravel
    networks: [apps]
    dns: [poisonstop]                # ou o IP fixo do poisonstop na rede apps
    environment:
      HTTP_PROXY: http://poisonstop:3128
      HTTPS_PROXY: http://poisonstop:3128
      NO_PROXY: mysql,redis,localhost
    labels:
      poisonstop.service: app        # nome que aparece no painel

networks:
  apps:
    internal: true
  egress: {}
```

### 5.2 Proxy (como o tráfego passa)
- **MVP: proxy explícito** HTTP/HTTPS (porta 3128) via `HTTP_PROXY`/`HTTPS_PROXY`. Quase todo cliente HTTP respeita (Guzzle, curl, Node, Python requests, Go).
- **HTTP:** lê o `Host` e decide.
- **HTTPS:** recebe `CONNECT host:443`, decide pelo host. **Não abre o TLS.** Depois do CONNECT, lê o **SNI** do ClientHello e confere se bate com o host pedido (impede pedir `CONNECT api.stripe.com` e mandar SNI de outro domínio).
- Conexão para **IP direto** (sem nome) é bloqueada por padrão em `enforce`.
- **Fase 2: modo transparente** para clientes que ignoram proxy: redirecionamento via iptables/nftables para o PoisonStop, que identifica o destino pelo SNI (TLS) ou pelo `Host` (HTTP). Tráfego não HTTP/TLS é negado ou liberado por regra IP:porta.

**Limitações conhecidas (documentar no README):**
- **ECH (Encrypted Client Hello)** esconde o SNI real. Em modo explícito o host do CONNECT já basta; em modo transparente, ECH precisa ser bloqueado (negar o DNS HTTPS/SVCB com chave ECH resolve na prática).
- **Domain fronting** em CDNs: o SNI pode ser um domínio permitido e o `Host` interno outro. Sem MITM não dá para ver. Mitigação: não liberar CDNs genéricas inteiras.

### 5.3 DNS filtrado (contra DNS tunneling)
- O PoisonStop roda um resolver próprio (porta 53 na rede `apps`).
- Só responde nomes que estejam na whitelist do serviço (em `enforce`); o resto recebe `NXDOMAIN` e vira log.
- Todas as consultas são registradas, inclusive as negadas. Subdomínios aleatórios e compridos (`a8f3k2...exemplo.com`) são o padrão clássico de vazamento por DNS e geram alerta.
- Como a rede é `internal`, o container não consegue falar com `8.8.8.8` direto. O único DNS que funciona é o do PoisonStop.
- Bônus: com proxy explícito, a aplicação nem precisa resolver nomes externos, quem resolve é o proxy.

### 5.4 Allowlist por host exato
- Regra padrão: **host exato** (`maps.googleapis.com`, `api.stripe.com`).
- Wildcard só quando o usuário escreve explicitamente (`*.s3.sa-east-1.amazonaws.com`), e o painel mostra aviso.
- Motivo: liberar `*.googleapis.com` deixa o atacante mandar dados para um bucket ou planilha **dele**, dentro do Google. "Só Google" é uma porta larga.
- Porta faz parte da regra (`api.stripe.com:443`).

Formato do arquivo de regras (`poisonstop.yml`):

```yaml
default_mode: learn          # learn | monitor | enforce
learn_period: 7d

services:
  app:
    mode: enforce
    allow:
      - api.stripe.com:443
      - maps.googleapis.com:443
      - vault.interno:8200
  worker:
    mode: monitor
    allow:
      - api.telegram.org:443

alerts:
  telegram:
    bot_token_env: POISONSTOP_TG_TOKEN
    chat_id: "123456"
  webhook:
    url: https://n8n.exemplo.com/webhook/poisonstop
```

### 5.5 Identificação do serviço
- Pelo **IP de origem** na rede `apps`, mapeado para o container.
- Para mapear IP → container, o PoisonStop consulta a API do Docker **somente leitura**, através de um `docker-socket-proxy` (nunca montar `/var/run/docker.sock` direto, isso seria dar root da máquina para o próprio componente de segurança).
- Nome exibido: label `poisonstop.service`, senão o nome do serviço do Compose.
- Alternativa sem acesso ao Docker: mapear IPs fixos no YAML.

### 5.6 Stack sugerida
- **Proxy, DNS e API:** **Go**. Biblioteca padrão já faz proxy HTTP/CONNECT; `miekg/dns` para o resolver. Binário único, imagem pequena (distroless/scratch), rápido e com pouco consumo.
- **Painel:** HTML servido pelo próprio binário (templates Go + **htmx** + Alpine.js + Tailwind), embutido com `embed`. Um container só, sem Node no runtime.
- **Banco:** **SQLite** (modo WAL) no volume `/data`. Agregação por hora para não crescer sem limite; retenção configurável (padrão 30 dias de detalhe).
- **Métricas:** endpoint `/metrics` para Prometheus (fase 2).

*Alternativa:* se quiser o painel em Laravel (sua stack), dá para separar em dois containers: proxy em Go gravando no SQLite/Postgres e um painel Laravel lendo. Funciona, mas o "um container só" é um diferencial grande de adoção, então a recomendação é começar tudo em Go.

### 5.7 Segurança do próprio PoisonStop
- Painel numa rede separada, publicado só em `127.0.0.1` ou atrás de VPN/Tailscale.
- Container sem root, filesystem read-only exceto `/data`.
- Falha fechada: se o PoisonStop cair, os serviços ficam sem internet (comportamento esperado e documentado), nunca com internet livre.
- Segredos de alerta lidos de variáveis de ambiente, nunca gravados no SQLite.

---

## 6. Roadmap

**v0.1, MVP (2 a 4 semanas)**
- Proxy explícito HTTP/CONNECT com checagem de SNI
- DNS filtrado com log
- Modos learn / monitor / enforce por serviço
- Whitelist sugerida a partir do aprendizado
- Painel: visão geral, por serviço, bloqueios, editar whitelist
- Alertas Telegram + webhook
- `docker-compose.yml` de exemplo e README com o passo a passo

**v0.2**
- Alertas por e-mail
- Detecção de DNS tunneling (entropia/tamanho de subdomínio)
- Import/export da whitelist em YAML pelo painel
- Endpoint Prometheus
- Lista de "destinos suspeitos" conhecidos (paste, upload, túnel)

**v0.3**
- Modo transparente (sem `HTTP_PROXY`), com nftables
- Regras para tráfego não HTTP (IP:porta, ex.: SMTP)
- Relatório semanal ("seus serviços falaram com N hosts, 2 novos")

**v1.0**
- Helm chart / modo Kubernetes (sidecar ou DaemonSet)
- Multiusuário com papéis
- Integração com GitHub Actions para gerar a whitelist já no CI
- Feeds de reputação de domínio

---

## 7. Licença sugerida

**Apache-2.0.**
- Permissiva, empresas adotam sem medo (importante para ferramenta de segurança ganhar tração).
- Inclui concessão de patentes, o que a MIT não tem.
- Padrão do ecossistema cloud native (Kubernetes, Envoy, Cilium usam Apache-2.0).

Alternativa: **AGPL-3.0**, se a preocupação for alguém pegar o projeto e vender como SaaS fechado. Fecha essa porta, mas afasta parte das empresas. Dá para começar em Apache-2.0 e, se um dia houver versão comercial, oferecer recursos extras à parte (modelo open core).

---

## 8. Primeiros passos para criar o repositório

1. Adicionar a licença Apache-2.0 ao repositório e completar o README com a seção 2 deste documento.
2. Estrutura inicial:
   ```
   cmd/poisonstop/       main.go
   internal/proxy/       HTTP + CONNECT + SNI
   internal/dns/         resolver filtrado
   internal/policy/      modos, whitelist, sugestão
   internal/store/       SQLite
   internal/alerts/      telegram, webhook
   internal/web/         painel (templates + htmx, embed)
   deploy/compose/       docker-compose.yml de exemplo
   docs/
   ```
3. Primeira entrega testável: proxy em modo `learn` gravando em SQLite + uma página listando "serviço → hosts". Já dá para rodar no seu próprio servidor e descobrir para onde suas aplicações mandam dados.
4. Abrir issues a partir do roadmap v0.1 para acompanhar o progresso.

---

## 9. Ideia de conteúdo para o canal

Série "**Eu monitorei para onde meus serviços mandam dados**":
1. O problema: pacote envenenado roubando chave (demo com um pacote de teste inofensivo tentando mandar o `.env` para fora).
2. Construindo o PoisonStop ao vivo / em episódios.
3. O resultado: o que apareceu no modo aprendizado dos meus próprios projetos.
4. A mesma demo do episódio 1, agora barrada, com o alerta chegando no Telegram.
