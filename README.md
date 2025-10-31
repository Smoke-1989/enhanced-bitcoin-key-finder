# Enhanced Bitcoin Key Finder - Versão Interativa

Ferramenta de alta performance em Go para busca de chaves privadas Bitcoin a partir de endereços conhecidos, com **interface interativa amigável**, processamento paralelo, modos sequencial e aleatório, e recursos avançados.

## 🎯 Objetivo do projeto

Fornecer um utilitário **educacional e experimental** para estudar geração de chaves na curva secp256k1, derivação de endereços P2PKH (comprimidos e não comprimidos) e técnicas de paralelismo/observabilidade em Go. O propósito é demonstrar engenharia de performance, I/O eficiente e UX de linha de comando, **não incentivar uso malicioso**. Use somente com endereços que você possui autorização explícita para testar.

## ✨ Principais Funcionalidades

### 🚀 Interface Totalmente Interativa
- **Menu principal intuitivo** com opções numeradas
- **Configuração rápida** para usuários iniciantes
- **Configuração avançada** para usuários experientes
- **Assistente de endereços** com validação automática
- **Criação automática** de arquivos de exemplo
- **Interface colorida** com emojis e feedback visual

### ⚡ Alta Performance
- Go 1.21+ com goroutines otimizadas
- Processamento paralelo configurável
- Controle automático de workers com limites de sanidade
- Geração criptograficamente segura de números aleatórios

### 🎛️ Modos de Busca
1. **Sequential**: Iteração determinística (1, 2, 3...)
2. **Random**: Amostragem aleatória no range especificado

### 🔧 Configurações Pré-definidas
- **Range Pequeno** (1-1,000,000): Testes rápidos, modo sequencial
- **Range Médio** (1-1,000,000,000): Testes extensos, modo aleatório
- **Range Completo** (secp256k1): Todo o espaço de chaves

### 💾 Recursos Avançados
- Progresso em tempo real (keys/s, contagem, tempo)
- Retomada automática de execução (modo sequencial)
- Salvamento em JSON formatado
- Interrupção graciosa com Ctrl+C
- Suporte a endereços P2PKH comprimidos e não comprimidos

## 📋 Requisitos

- **Go 1.21** ou superior
- **Windows, Linux** ou **macOS**
- CPU multi-core recomendado
- **RAM**: 4GB+ (8GB+ recomendado)

## 🚀 Instalação e Uso

### Passo 1: Clonar e Preparar
```bash
# Clonar o repositório
git clone https://github.com/Smoke-1989/enhanced-bitcoin-key-finder.git
cd enhanced-bitcoin-key-finder

# Instalar dependências
go mod tidy
```

### Passo 2: Compilar
```bash
# Build otimizado
go build -trimpath -ldflags="-s -w" -o enhanced_key_finder enhanced_key_finder.go
```

### Passo 3: Executar (Modo Interativo)
```bash
# Windows
enhanced_key_finder.exe

# Linux/macOS
./enhanced_key_finder
```

## 🎮 Como Usar a Interface Interativa

### Menu Principal
Ao executar o programa, você verá:

```
============================================================
        ENHANCED BITCOIN KEY FINDER - VERSÃO INTERATIVA
           Ferramenta Educacional de Busca de Chaves
============================================================

📋 MENU PRINCIPAL:
1. 🔧 Configuração Rápida (Recomendado)
2. ⚙️  Configuração Avançada
3. 📄 Carregar Configuração Salva
4. ❓ Ajuda
5. 🚪 Sair

Escolha uma opção (1-5):
```

### 1. Configuração Rápida 🔧
Para usuários iniciantes - escolha um dos modos pré-configurados:

- **Range Pequeno**: Busca sequencial em 1-1,000,000 (ideal para testes)
- **Range Médio**: Busca aleatória em 1-1,000,000,000 (testes extensos)
- **Range Completo**: Busca aleatória em todo espaço secp256k1 (educacional)

### 2. Configuração Avançada ⚙️
Para usuários experientes - controle total:

- Escolha do modo (Sequential/Random)
- Definição de range customizado (min/max em hex)
- Número de workers personalizado
- Opções de salvamento e parada
- Configuração de arquivos de saída

### 3. Configuração de Endereços 📭
O programa oferece três opções:

1. **Carregar arquivo** `address.json`
2. **Inserir manualmente** com validação
3. **Usar exemplo** (Genesis Block)

#### Formatos suportados para `address.json`:
```json
{"address": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"]}
```
ou
```json
["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX"]
```

### 4. Interface de Busca 🔍
Durante a execução você verá:

```
🚀 Iniciando busca - Modo: random | Workers: 8
🔄 Gerando chaves... 15432 keys/s [████████████████] 156,234 keys
```

**Se encontrar uma chave:**
```
🎉 [ENCONTRADO!] Chave: 000000000000000000000000000000000000000000000000000000000000002a
    Endereços: [1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa]
```

## 📊 Arquivos de Saída

### `found_keys.json` - Chaves Encontradas
```json
{
  "results": [
    {
      "private_key_hex": "000000000000000000000000000000000000000000000000000000000000002a",
      "addresses": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
      "compressed": true,
      "timestamp": "2025-10-31T17:12:00Z"
    }
  ]
}
```

### `progress.json` - Estado de Progresso
```json
{
  "last_checked_hex": "000000000000000000000000000000000000000000000000000000000000ff2a",
  "count_checked": "1048576",
  "started_at": "2025-10-31T17:00:00Z",
  "mode": "sequential"
}
```

## ⚡ Dicas de Performance

### Configuração de Workers
- **CPUs sem hyperthreading**: Use número de cores físicos
- **CPUs com hyperthreading**: Teste com metade dos threads disponíveis
- **Exemplo**: CPU 8 cores/16 threads → começar com 8 workers

### Estratégias de Range
- **Ranges pequenos**: Use modo Sequential para cobertura completa
- **Ranges enormes**: Use modo Random e divida em segmentos
- **Testes educacionais**: Use ranges pequenos primeiro

### Gerenciamento de Recursos
- Evite `Salvar todas as chaves` (gera arquivos gigantes)
- Use `Parar ao encontrar` para economizar recursos
- Monitor uso de memória com ranges muito grandes

## 🛡️ Segurança e Avisos

### ⚠️ Avisos Importantes
- **O espaço de chaves Bitcoin é astronomicamente grande**
- **A chance de encontrar chaves reais é praticamente ZERO**
- **Use apenas para fins educacionais e de pesquisa**
- **Não use contra endereços de terceiros sem autorização**

### 🔒 Boas Práticas
- Não compartilhe arquivos `found_keys.json`
- Execute em ambientes confiáveis e rede segura
- Use storage criptografado para dados sensíveis
- Mantenha backups de configurações importantes

## 🔧 Solução de Problemas

### Problemas Comuns

**Erro de compilação:**
```bash
# Se houver problemas com dependências
go clean -modcache
go mod tidy
go build enhanced_key_finder.go
```

**Uso alto de memória:**
- Reduza o número de workers
- Use ranges menores
- Desative "salvar todas as chaves"

**Performance baixa:**
- Aumente workers moderadamente
- Verifique carga do sistema
- Use modo Random para ranges grandes

**Erros de arquivo:**
- Verifique permissões de escrita
- Confirme formato do `address.json`
- Verifique espaço em disco

## 🎓 Detalhes Técnicos

### Criptografia
- **Curva**: secp256k1
- **Range máximo**: `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140`
- **Geração aleatória**: `crypto/rand` (criptograficamente seguro)

### Endereços
- **Tipo**: P2PKH mainnet (version byte 0x00)
- **Processo**: Chave Pública → SHA256 → RIPEMD-160 → Base58Check
- **Formatos**: Comprimido e não comprimido

### Arquitetura
- **Paralelismo**: Goroutines com canal distribuidor
- **Controle**: Context para cancelamento gracioso
- **Performance**: Workers com limite de sanidade automático

## 📄 Licença

**MIT License** - Consulte o arquivo LICENSE para detalhes completos.

## ⚖️ Aviso Legal

Este software é fornecido **exclusivamente para fins educacionais, experimentais e de pesquisa** em segurança/criptografia. Não há garantia de encontrar chaves correspondentes em tempo realista. O espaço de chaves é astronomicamente grande (2^256). Não utilize contra ativos ou endereços de terceiros sem autorização expressa.

## 🤝 Contribuições

Contribuições são bem-vindas! Áreas de interesse:

- ✨ Melhorias na interface interativa
- ⚡ Otimizações de performance
- 🔧 Novas estratégias de geração
- 📊 Funcionalidades de telemetria
- 🌍 Internacionalização
- 📱 Interface web/GUI

### Como Contribuir
1. Fork o repositório
2. Crie uma branch para sua feature
3. Implemente e teste suas mudanças
4. Envie um Pull Request

---

**💡 Dica**: Para uma experiência otimizada, use um terminal que suporte cores e emojis! O programa funcionará em qualquer terminal, mas a experiência visual será melhor.

**🎯 Lembre-se**: Esta é uma ferramenta educacional. O foco está no aprendizado de conceitos de criptografia, paralelismo e engenharia de software, não na busca real de chaves privadas.