# PoisonStop

> Your dependencies can read your secrets. They just can't send them anywhere.

Proxy de saída (egress) com painel para Docker. Ele registra para onde cada serviço manda requisições, sugere a whitelist sozinho (modo aprendizado) e bloqueia o resto (modo bloqueio), com alertas quando algo novo ou bloqueado aparece.

O objetivo é fechar a porta mais usada por pacotes envenenados e RCEs: mesmo que o código malicioso leia suas chaves, ele não consegue mandá-las para fora.

**Status:** ideia / especificação do MVP.

Leia a especificação completa em [docs/ESPECIFICACAO.md](docs/ESPECIFICACAO.md).
