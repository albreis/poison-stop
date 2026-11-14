# PoisonStop

> Your dependencies can read your secrets. They just can't send them anywhere.

Proxy de saída (egress) com painel para Docker. Ele registra para onde cada serviço manda requisições, sugere a whitelist sozinho (modo aprendizado) e bloqueia o resto (modo bloqueio), com alertas quando algo novo ou bloqueado aparece.

O objetivo é fechar a porta mais usada por pacotes envenenados e RCEs: mesmo que o código malicioso leia suas chaves, ele não consegue mandá-las para fora.

**Status:** primeira entrega testável. O proxy explícito e o DNS filtrado gravam em SQLite para onde cada serviço fala, e o painel mostra serviço → hosts e as consultas DNS. Os modos `monitor` e `enforce` já funcionam pelo `poisonstop.yml`, com alertas por Telegram e webhook; login e edição da whitelist pelo painel vêm a seguir (veja o [roadmap](docs/ESPECIFICACAO.md#6-roadmap)).

Leia a especificação completa em [docs/ESPECIFICACAO.md](docs/ESPECIFICACAO.md).

## Por quê

Um pacote do npm, do Composer ou do PyPI comprometido roda no `postinstall` ou no boot da aplicação, lê variáveis de ambiente, `.env` e tokens, e manda tudo para um servidor do atacante. O que esses ataques têm em comum é **a saída**. Se o serviço só consegue falar com os hosts que ele realmente usa, a chave roubada fica presa dentro do container.

Docker, por padrão, deixa todo container falar com a internet inteira, e quase ninguém sabe responder "para quais hosts o meu serviço de pagamento manda requisições?". O PoisonStop responde isso e depois fecha o resto.

## Rodando o exemplo (5 minutos)

Precisa de Docker com Compose.

```bash
cd deploy/compose
docker compose up -d --build
```

Abra <http://127.0.0.1:8080> e entre como `admin`. A senha é gerada na primeira subida e aparece uma única vez no log (ou defina `POISONSTOP_ADMIN_PASSWORD` antes de subir):

```bash
docker compose logs poisonstop | grep senha
```

Em menos de um minuto aparecem os serviços `app` e `worker` com os hosts que cada um acessou. O `worker` também tenta falar com a internet sem passar pelo proxy, e essa tentativa falha, porque a rede `apps` é `internal`:

```bash
docker compose logs -f worker
```

O `worker` está em `monitor`, liberado só para o Telegram. A conexão dele para `1.1.1.1` passa, mas gera um alerta que chega no webhook de exemplo:

```bash
docker compose logs alert-sink
```

Para desligar:

```bash
docker compose down
```

## Como funciona

```
                internet
                   ▲
                   │ (só o PoisonStop sai)
       ┌───────────┴────────────┐
       │      poisonstop        │  painel 127.0.0.1:8080
       │   proxy :3128 · painel │
       └───────────┬────────────┘
                   │  rede "apps" (internal: true)
           ┌───────┴───────┐
       ┌───┴───┐       ┌───┴───┐
       │  app  │       │worker │
       └───────┘       └───────┘
```

- Os serviços ficam numa rede Docker `internal: true`, sem rota para a internet. O `poisonstop` é o único container nas redes `apps` e `egress`, então não dá para "pular" o proxy.
- Os serviços usam `HTTP_PROXY`/`HTTPS_PROXY=http://poisonstop:3128`. Quase todo cliente HTTP respeita (curl, Guzzle, Node, Python requests, Go).
- **HTTP:** o proxy lê o host da URL e decide.
- **HTTPS:** o proxy recebe `CONNECT host:443`, decide pelo host e **não abre o TLS**. Ele lê o SNI do ClientHello e marca (ou, em `enforce`, derruba) a conexão se o SNI não bater com o host pedido.
- **Qual serviço é qual:** pelo IP de origem, consultando a API do Docker somente leitura através de um [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) (nunca monte `/var/run/docker.sock` direto no PoisonStop). O nome exibido é a label `poisonstop.service`, senão o serviço do Compose. Sem Docker, dá para mapear IPs fixos em `identify.static_ips`.
- **DNS filtrado:** os serviços usam `dns: [10.89.0.2]` (o IP do PoisonStop na rede `apps`). Todas as consultas são registradas, inclusive as negadas; em `enforce`, só nomes da whitelist resolvem e o resto recebe `NXDOMAIN`. Como a rede é `internal`, o container não consegue usar outro DNS (ex.: `8.8.8.8`), o que fecha o caminho do DNS tunneling. Nomes de containers continuam resolvidos pelo DNS embutido do Docker.
- Tudo vai para um SQLite (modo WAL) em `/data`, com totais por destino e por hora.
- O painel recusa acessos vindos das redes em `panel.deny_cidrs` (a rede dos serviços monitorados) e deve ser publicado só em `127.0.0.1` ou atrás de VPN.

## Painel

- **Visão geral:** serviços, modo de cada um, quantos destinos estão na whitelist e bloqueios nas últimas 24h. Serviços em `learn` mostram quanto falta para o fim do `learn_period`.
- **Por serviço:** gráfico de conexões por hora, destinos com volume e primeira/última vez, **whitelist sugerida** (já marcada para o que foi usado e não é suspeito; IP direto, paste/upload/túnel e SNI estranho vêm desmarcados), troca de modo, adicionar e remover regras, consultas DNS.
- **Bloqueios:** tentativas negadas pelo proxy e pelo DNS, com botão "liberar este host".
- **Whitelist:** todas as regras em YAML, para baixar ou importar (substitui tudo).

Login com usuário e senha (bcrypt), sessão por cookie `HttpOnly`/`SameSite=Strict`, POST de outra origem recusado. O painel recusa acessos vindos de `panel.deny_cidrs` e deve ficar só em `127.0.0.1` ou atrás de VPN.

## Configuração (`poisonstop.yml`)

As regras de `services` **semeiam o banco na primeira subida**. Depois disso, a fonte das regras é o painel (que importa e exporta o mesmo formato YAML); mudar o arquivo não altera um banco já existente.

```yaml
default_mode: learn          # learn | monitor | enforce
learn_period: 7d

proxy:
  listen: ":3128"
dns:
  listen: ":53"                  # vazio desliga
  # upstream: 1.1.1.1:53         # padrão: DNS do próprio container
panel:
  listen: ":8080"
  deny_cidrs: ["10.89.0.0/24"]   # rede "apps"
identify:
  docker_host: http://docker-proxy:2375
data:
  path: /data/poisonstop.db

services:
  app:
    mode: enforce
    allow:
      - api.stripe.com:443
      - maps.googleapis.com          # sem porta = 443
      - "*.s3.sa-east-1.amazonaws.com:443"
  worker:
    mode: monitor
    allow:
      - api.telegram.org:443
```

| Modo | O que faz |
|---|---|
| `learn` | Deixa tudo passar e registra. |
| `monitor` | Deixa tudo passar, mas marca o que está fora da whitelist. |
| `enforce` | Só passa o que está na whitelist. HTTP recebe 403; `CONNECT` recebe 403. IP direto sem nome é bloqueado. O DNS só resolve nomes da whitelist. |

Regras da whitelist: host exato com porta (`api.stripe.com:443`). Wildcard só quando escrito explicitamente (`*.dominio:443`) e só casa subdomínios. Liberar `*.googleapis.com` deixa o atacante mandar dados para um bucket **dele** dentro do Google, então prefira o host exato.

## Alertas

```yaml
alerts:
  debounce: 10m                  # 1 alerta por serviço+evento+host nesse intervalo
  telegram:
    bot_token_env: POISONSTOP_TG_TOKEN
    chat_id: "123456"
  webhook:
    url: https://n8n.exemplo.com/webhook/poisonstop
    secret_env: POISONSTOP_WEBHOOK_SECRET   # opcional: assina o corpo
```

| Evento | Quando |
|---|---|
| `blocked` | Conexão bloqueada em `enforce` (inclui SNI diferente do `CONNECT`). |
| `dns_denied` | Consulta DNS negada em `enforce`. |
| `off_list` | Serviço em `monitor` falou com destino fora da whitelist. |
| `sni_mismatch` | SNI do TLS diferente do host pedido no `CONNECT` (learn/monitor). |
| `new_host` | Serviço em `learn`, já depois do `learn_period`, falou com um destino nunca visto. |

O webhook recebe um JSON com `event`, `service`, `host`, `port`, `proto`, `mode`, `detail`, `time`, `suppressed` (quantos alertas iguais foram agrupados) e `text` (mensagem pronta). Com `secret_env`, o cabeçalho `X-PoisonStop-Signature: sha256=<hmac>` permite validar a origem. Tokens e segredos vêm só de variáveis de ambiente, nunca do arquivo nem do banco.

## Desenvolvimento

Não precisa de Go instalado; dá para testar dentro de um container:

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.26-alpine go test ./...
```

Estrutura:

```
cmd/poisonstop/       main.go
internal/config/      leitura do poisonstop.yml
internal/proxy/       HTTP + CONNECT + SNI
internal/identify/    IP de origem -> serviço (Docker / IPs fixos)
internal/policy/      modos, whitelist, hosts suspeitos
internal/store/       SQLite
internal/web/         painel (templates embutidos)
internal/dns/         resolver filtrado
internal/alerts/      Telegram, webhook, debounce
deploy/compose/       docker-compose.yml de exemplo
docs/                 especificação
```

## Limitações conhecidas

- **Clientes que ignoram proxy** não conseguem sair (a rede `apps` é `internal`), mas também não aparecem no painel até existir o modo transparente (roadmap v0.3).
- **ECH (Encrypted Client Hello)** esconde o SNI real. No modo explícito o host do `CONNECT` já basta para decidir.
- **Domain fronting** em CDNs: o SNI pode ser um domínio permitido e o `Host` interno outro. Sem abrir o TLS não dá para ver. Não libere CDNs genéricas inteiras.
- **Falha fechada:** se o PoisonStop cair, os serviços ficam sem internet. É de propósito.

## Licença

[Apache-2.0](LICENSE).
