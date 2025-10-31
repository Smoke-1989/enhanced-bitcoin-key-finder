# Enhanced Bitcoin Key Finder

Ferramenta de alta performance em Go para busca de chaves privadas Bitcoin a partir de endereços conhecidos, com processamento paralelo, modos sequencial e aleatório, interface interativa e retomada segura de progresso.

## Objetivo do projeto

Fornecer um utilitário educacional e experimental para estudar geração de chaves na curva secp256k1, derivação de endereços P2PKH (comprimidos e não comprimidos) e técnicas de paralelismo/observabilidade em Go. O propósito é demonstrar engenharia de performance, I/O eficiente e UX de linha de comando, não incentivar uso malicioso. Use somente com endereços que você possui autorização explícita para testar.

## Funcionalidades

- Alta performance em Go 1.21+ com goroutines e canais.
- Dois modos de geração de chaves:
  - Sequencial: iteração determinística dentro do range.
  - Aleatório: amostragem criptograficamente segura no range.
- Suporte a endereços P2PKH comprimidos e não comprimidos (prefixo 1 em mainnet).
- Processamento paralelo com controle de workers e limite de sanidade.
- Progresso em tempo real: throughput (keys/s), contagem e tempo decorrido.
- Retomada de execução: grava e lê progress.json (modo sequencial).
- Salvamento de resultados em found_keys.json (JSON formatado).
- Interrupção graciosa com Ctrl+C e limpeza de estado.
- Interface colorida (mensagens) e barra de progresso/spinner.

## Requisitos

- Go 1.21 ou superior
- Windows, Linux ou macOS
- CPU multi-core recomendado; RAM 4GB+ (8GB+ recomendado)

## Instalação

```bash
# Clonar o repositório
git clone https://github.com/Smoke-1989/enhanced-bitcoin-key-finder.git
cd enhanced-bitcoin-key-finder

# Instalar dependências
go mod tidy
```

## Build

```bash
# Build otimizado
go build -trimpath -ldflags="-s -w" -o enhanced_key_finder enhanced_key_finder.go
```

## Uso

Arquivos de entrada:
- address.json pode ser nos dois formatos:
  ```json
  {"address": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"]}
  ```
  ou
  ```json
  ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"]
  ```

Execução típica:
```bash
# Modo aleatório em mainnet range completo, 8 workers
./enhanced_key_finder \
  -addresses address.json \
  -mode random \
  -workers 8 \
  -min 1 \
  -max FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
```

Parâmetros principais:
- -addresses: caminho do address.json (padrão: address.json)
- -addr: passar um único endereço manualmente (ignora o arquivo)
- -mode: sequential | random (padrão: sequential)
- -min / -max: range em hex dentro de secp256k1 (inclusive)
- -workers: número de goroutines (recomendado ≈ núcleos)
- -out: arquivo de saída dos achados (padrão: found_keys.json)
- -progress: arquivo de progresso (padrão: progress.json)
- -resume: retomar de progresso salvo (padrão: true; seq. apenas)
- -save-all: salvar todas as chaves testadas (cuidado com tamanho)
- -stop-on-found: parar ao encontrar qualquer match

## Formato de saída

- found_keys.json:
  ```json
  {
    "results": [
      {
        "private_key_hex": "...",
        "addresses": ["1...", "1..."],
        "compressed": true,
        "timestamp": "2025-10-31T14:12:00Z"
      }
    ]
  }
  ```
- progress.json (modo sequencial): última chave verificada e contagem.

## Dicas de performance

- Ajuste -workers ao número de cores físicos; em CPUs com hyperthreading, testar metade dos threads pode reduzir contenção.
- Para ranges enormes, use -mode random e fatie o espaço em execuções menores.
- Evite -save-all, pois gera arquivos muito grandes e degrada I/O.

## Segurança

- Não compartilhe chaves privadas registradas em found_keys.json.
- Execute apenas em ambientes confiáveis e rede segura.
- Use storage criptografado para artefatos sensíveis.

## Solução de problemas

- Uso alto de memória: reduza o range, diminua -workers, use modo sequential.
- Performance baixa: aumente -workers moderadamente, verifique carga do sistema, reduza o range.
- Erros de arquivo: valide permissões, formato do address.json e espaço em disco.

## Detalhes técnicos

- Curva: secp256k1; limite superior: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
- Endereços derivados P2PKH mainnet (version byte 0x00) a partir da chave pública (SHA256, RIPEMD-160, Base58Check)
- Paralelismo com canais, controle de workers e cancelamento via contexto

## Licença

MIT. Consulte o arquivo LICENSE.

## Aviso legal

Este software é fornecido exclusivamente para fins educacionais, experimentais e de pesquisa em segurança/ofuscação de espaço de chaves. Não há garantia de encontrar chaves correspondentes em espaço realista; o espaço de chaves é astronomicamente grande. Não utilize contra ativos ou endereços de terceiros sem autorização expressa.

## Contribuições

Issues e PRs são bem-vindos. Otimizações de performance, melhorias de UX/telemetria e novas estratégias de geração são especialmente bem-vindas.
