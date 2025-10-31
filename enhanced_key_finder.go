// enhanced_key_finder.go
// Enhanced Bitcoin Key Finder - Versão Interativa
// Licença: MIT
// Build: go build -trimpath -ldflags="-s -w" enhanced_key_finder.go

package main

import (
	"bufio"
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"golang.org/x/crypto/ripemd160"
)

const (
	// Ordem do grupo secp256k1
	secpNHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
	minHex   = "1"

	defaultFoundFile   = "found_keys.json"
	defaultProgress    = "progress.json"
	defaultAddressFile = "address.json"
)

// Tipos e estruturas

type Mode string

const (
	ModeSequential Mode = "sequential"
	ModeRandom     Mode = "random"
)

type Config struct {
	Addresses     []string
	Mode          Mode
	Workers       int
	MinHex        string
	MaxHex        string
	SaveAll       bool
	StopOnFound   bool
	FoundFile     string
	ProgressFile  string
	Resume        bool
}

type TargetSet struct {
	Addrs map[string]struct{}
}

type FoundKey struct {
	PrivateKeyHex string   `json:"private_key_hex"`
	Addresses     []string `json:"addresses"`
	Compressed    bool     `json:"compressed"`
	Timestamp     string   `json:"timestamp"`
}

type FoundResult struct {
	Results []FoundKey `json:"results"`
}

type ProgressState struct {
	LastCheckedHex string `json:"last_checked_hex"`
	CountChecked   string `json:"count_checked"`
	StartedAt      string `json:"started_at"`
	Mode           string `json:"mode"`
	MinHex         string `json:"min_hex"`
	MaxHex         string `json:"max_hex"`
}

type InputAddresses struct {
	Address []string `json:"address"`
}

// Cores para interface
var (
	colorTitle  = color.New(color.FgCyan, color.Bold)
	colorMenu   = color.New(color.FgYellow)
	colorInput  = color.New(color.FgGreen)
	colorError  = color.New(color.FgRed)
	colorInfo   = color.New(color.FgBlue)
	colorFound  = color.New(color.FgGreen, color.Bold)
)

// Interface interativa

func printHeader() {
	colorTitle.Println("\n" + strings.Repeat("=", 60))
	colorTitle.Println("        ENHANCED BITCOIN KEY FINDER - VERSÃO INTERATIVA")
	colorTitle.Println("           Ferramenta Educacional de Busca de Chaves")
	colorTitle.Println(strings.Repeat("=", 60))
	fmt.Println()
}

func showMainMenu() {
	colorMenu.Println("\n📋 MENU PRINCIPAL:")
	fmt.Println("1. 🔧 Configuração Rápida (Recomendado)")
	fmt.Println("2. ⚙️  Configuração Avançada")
	fmt.Println("3. 📄 Carregar Configuração Salva")
	fmt.Println("4. ❓ Ajuda")
	fmt.Println("5. 🚪 Sair")
	colorInput.Print("\nEscolha uma opção (1-5): ")
}

func showQuickSetupMenu() {
	colorMenu.Println("\n⚡ CONFIGURAÇÃO RÁPIDA:")
	fmt.Println("1. 🎯 Busca em Range Pequeno (1-1000000) - Sequencial")
	fmt.Println("2. 🔀 Busca Aleatória em Range Médio (1-1000000000) ")
	fmt.Println("3. 🌐 Busca Aleatória em Range Completo (secp256k1)")
	fmt.Println("4. ↩️  Voltar ao Menu Principal")
	colorInput.Print("\nEscolha uma opção (1-4): ")
}

func getUserInput(prompt string) string {
	colorInput.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func getUserConfirmation(prompt string) bool {
	response := strings.ToLower(getUserInput(prompt + " (s/n): "))
	return response == "s" || response == "sim" || response == "y" || response == "yes"
}

func loadAddressesInteractive() ([]string, error) {
	colorMenu.Println("\n📍 CONFIGURAÇÃO DE ENDEREÇOS:")
	fmt.Println("1. 📁 Carregar do arquivo address.json")
	fmt.Println("2. ✏️  Inserir manualmente")
	fmt.Println("3. 🧪 Usar endereço de exemplo (Genesis Block)")

	choice := getUserInput("Escolha uma opção (1-3): ")

	switch choice {
	case "1":
		return loadAddressesFromFile()
	case "2":
		return inputAddressesManually()
	case "3":
		return []string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}, nil // Genesis block
	default:
		return nil, errors.New("opção inválida")
	}
}

func loadAddressesFromFile() ([]string, error) {
	filename := getUserInput("Nome do arquivo (padrão: address.json): ")
	if filename == "" {
		filename = defaultAddressFile
	}

	if _, err := os.Stat(filename); err != nil {
		colorError.Printf("Arquivo não encontrado: %s\n", filename)
		if getUserConfirmation("Deseja criar um arquivo de exemplo?") {
			return createExampleAddressFile(filename)
		}
		return nil, err
	}

	return loadAddresses(filename)
}

func inputAddressesManually() ([]string, error) {
	var addresses []string
	colorInfo.Println("\nInsira os endereços Bitcoin (pressione Enter em branco para finalizar):")

	for i := 1; ; i++ {
		addr := getUserInput(fmt.Sprintf("Endereço %d: ", i))
		if addr == "" {
			break
		}
		if isValidBitcoinAddress(addr) {
			addresses = append(addresses, addr)
			colorInfo.Printf("✅ Endereço %d adicionado\n", i)
		} else {
			colorError.Printf("❌ Endereço inválido, tente novamente\n")
			i-- // Não incrementa o contador
		}
	}

	if len(addresses) == 0 {
		return nil, errors.New("nenhum endereço válido inserido")
	}

	return addresses, nil
}

func createExampleAddressFile(filename string) ([]string, error) {
	exampleAddrs := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // Genesis
		"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX", // Exemplo
	}

	exampleFile := InputAddresses{Address: exampleAddrs}
	data, _ := json.MarshalIndent(exampleFile, "", "  ")

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return nil, err
	}

	colorInfo.Printf("✅ Arquivo de exemplo criado: %s\n", filename)
	return exampleAddrs, nil
}

func isValidBitcoinAddress(addr string) bool {
	// Validação básica de endereço Bitcoin P2PKH
	return len(addr) >= 26 && len(addr) <= 35 && (addr[0] == '1' || addr[0] == '3')
}

func quickSetup() (*Config, error) {
	for {
		showQuickSetupMenu()
		choice := getUserInput("")

		switch choice {
		case "1":
			return createQuickConfig("1", "1000000", ModeSequential, 2)
		case "2":
			return createQuickConfig("1", "1000000000", ModeRandom, 4)
		case "3":
			return createQuickConfig("1", secpNHex, ModeRandom, runtime.NumCPU())
		case "4":
			return nil, errors.New("voltar")
		default:
			colorError.Println("❌ Opção inválida")
		}
	}
}

func createQuickConfig(min, max string, mode Mode, workers int) (*Config, error) {
	addresses, err := loadAddressesInteractive()
	if err != nil {
		return nil, err
	}

	config := &Config{
		Addresses:    addresses,
		Mode:         mode,
		Workers:      workers,
		MinHex:       min,
		MaxHex:       max,
		SaveAll:      false,
		StopOnFound:  true,
		FoundFile:    defaultFoundFile,
		ProgressFile: defaultProgress,
		Resume:       true,
	}

	showConfigSummary(config)
	return config, nil
}

func advancedSetup() (*Config, error) {
	addresses, err := loadAddressesInteractive()
	if err != nil {
		return nil, err
	}

	config := &Config{
		Addresses: addresses,
	}

	// Modo de busca
	colorMenu.Println("\n🔄 MODO DE BUSCA:")
	fmt.Println("1. Sequential (Sequencial - mais previsível)")
	fmt.Println("2. Random (Aleatório - mais eficiente para ranges grandes)")
	modeChoice := getUserInput("Escolha o modo (1-2): ")
	if modeChoice == "2" {
		config.Mode = ModeRandom
	} else {
		config.Mode = ModeSequential
	}

	// Range de busca
	colorMenu.Println("\n📏 RANGE DE BUSCA:")
	config.MinHex = getUserInput("Valor mínimo (hex, padrão: 1): ")
	if config.MinHex == "" {
		config.MinHex = "1"
	}

	config.MaxHex = getUserInput("Valor máximo (hex, padrão: completo): ")
	if config.MaxHex == "" {
		config.MaxHex = secpNHex
	}

	// Workers
	colorMenu.Println("\n👷 CONFIGURAÇÃO DE WORKERS:")
	colorInfo.Printf("CPU detectada: %d cores\n", runtime.NumCPU())
	workersInput := getUserInput(fmt.Sprintf("Número de workers (padrão: %d): ", runtime.NumCPU()))
	if workersInput == "" {
		config.Workers = runtime.NumCPU()
	} else {
		if w, err := strconv.Atoi(workersInput); err == nil && w > 0 {
			config.Workers = w
		} else {
			config.Workers = runtime.NumCPU()
		}
	}

	// Opções avançadas
	colorMenu.Println("\n⚙️ OPÇÕES AVANÇADAS:")
	config.SaveAll = getUserConfirmation("Salvar todas as chaves testadas? (ATENÇÃO: gera arquivos grandes)")
	config.StopOnFound = getUserConfirmation("Parar ao encontrar primeira chave?")
	config.Resume = getUserConfirmation("Habilitar retomada de progresso?")

	// Arquivos de saída
	colorMenu.Println("\n📁 ARQUIVOS DE SAÍDA:")
	foundFile := getUserInput(fmt.Sprintf("Arquivo para chaves encontradas (padrão: %s): ", defaultFoundFile))
	if foundFile == "" {
		config.FoundFile = defaultFoundFile
	} else {
		config.FoundFile = foundFile
	}

	progressFile := getUserInput(fmt.Sprintf("Arquivo de progresso (padrão: %s): ", defaultProgress))
	if progressFile == "" {
		config.ProgressFile = defaultProgress
	} else {
		config.ProgressFile = progressFile
	}

	showConfigSummary(config)
	return config, nil
}

func showConfigSummary(config *Config) {
	colorMenu.Println("\n📋 RESUMO DA CONFIGURAÇÃO:")
	fmt.Printf("🎯 Endereços alvo: %d\n", len(config.Addresses))
	fmt.Printf("🔄 Modo: %s\n", config.Mode)
	fmt.Printf("👷 Workers: %d\n", config.Workers)
	fmt.Printf("📏 Range: %s a %s\n", config.MinHex, config.MaxHex)
	fmt.Printf("💾 Arquivo de saída: %s\n", config.FoundFile)
	fmt.Printf("📊 Arquivo de progresso: %s\n", config.ProgressFile)
	fmt.Printf("🛑 Parar ao encontrar: %v\n", config.StopOnFound)
	fmt.Printf("💿 Salvar todas: %v\n", config.SaveAll)

	if !getUserConfirmation("\nConfirmar configuração e iniciar busca?") {
		colorError.Println("❌ Operação cancelada")
		os.Exit(0)
	}
}

func showHelp() {
	colorTitle.Println("\n❓ AJUDA - ENHANCED BITCOIN KEY FINDER")
	colorTitle.Println(strings.Repeat("-", 50))

	colorMenu.Println("\n🎯 O QUE FAZ:")
	fmt.Println("Este programa busca chaves privadas Bitcoin correspondentes a endereços")
	fmt.Println("específicos. É uma ferramenta EDUCACIONAL para estudo de criptografia.")

	colorMenu.Println("\n🔧 MODOS DE BUSCA:")
	fmt.Println("• Sequential: Testa chaves em ordem (1, 2, 3...)")
	fmt.Println("• Random: Testa chaves aleatoriamente no range especificado")

	colorMenu.Println("\n📏 RANGES SUGERIDOS:")
	fmt.Println("• Pequeno (1-1000000): Para testes rápidos")
	fmt.Println("• Médio (1-1000000000): Para testes mais extensos")
	fmt.Println("• Completo: Todo o espaço secp256k1 (MUITO grande)")

	colorMenu.Println("\n⚠️  AVISOS IMPORTANTES:")
	colorError.Println("• O espaço de chaves Bitcoin é ASTRONOMICAMENTE grande")
	colorError.Println("• A chance de encontrar chaves reais é praticamente ZERO")
	colorError.Println("• Use apenas para fins educacionais e de pesquisa")
	colorError.Println("• Não use contra endereços de terceiros sem autorização")

	colorMenu.Println("\n📁 FORMATOS DE ARQUIVO:")
	fmt.Println(`address.json formato 1: {"address": ["1A1z...", "12c6..."]}`) 
	fmt.Println(`address.json formato 2: ["1A1z...", "12c6..."]`)

	getUserInput("\nPressione Enter para continuar...")
}

// Funções principais do programa original (adaptadas)

func base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := new(big.Int).SetBytes(input)
	var out []byte
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}

	for _, b := range input {
		if b == 0x00 {
			out = append(out, alphabet[0])
		} else {
			break
		}
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func checksum(input []byte) []byte {
	first := chainhash.DoubleHashB(input)
	return first[:4]
}

func pubKeyToP2PKHAddress(pubkey []byte, compressed bool) string {
	sha := chainhash.HashB(pubkey)
	h := ripemd160.New()
	_, _ = h.Write(sha)
	pubKeyHash := h.Sum(nil)
	payload := append([]byte{0x00}, pubKeyHash...)
	full := append(payload, checksum(payload)...)
	return base58Encode(full)
}

func deriveAddressesFromPriv(priv *btcec.PrivateKey) (compressedAddr, uncompressedAddr string) {
	compressedPub := priv.PubKey().SerializeCompressed()
	uncompressedPub := priv.PubKey().SerializeUncompressed()
	return pubKeyToP2PKHAddress(compressedPub, true), pubKeyToP2PKHAddress(uncompressedPub, false)
}

func loadAddresses(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var obj InputAddresses
	if err := json.Unmarshal(data, &obj); err == nil && len(obj.Address) > 0 {
		return obj.Address, nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}
	return nil, errors.New("formato inválido de address.json")
}

func toTargetSet(addrs []string) TargetSet {
	m := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a != "" {
			m[a] = struct{}{}
		}
	}
	return TargetSet{Addrs: m}
}

func saveProgress(path string, ps ProgressState) {
	_ = os.WriteFile(path, mustJSON(ps), 0o644)
}

func loadProgress(path string) (ProgressState, error) {
	var ps ProgressState
	data, err := os.ReadFile(path)
	if err != nil {
		return ps, err
	}
	if err := json.Unmarshal(data, &ps); err != nil {
		return ps, err
	}
	return ps, nil
}

func appendFound(path string, fk FoundKey) error {
	var fr FoundResult
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &fr)
	}
	fr.Results = append(fr.Results, fk)
	return os.WriteFile(path, mustJSONIndent(fr), 0o600)
}

func parseHexBig(s string) (*big.Int, error) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if s == "" {
		return nil, errors.New("hex vazio")
	}
	n := new(big.Int)
	_, ok := n.SetString(s, 16)
	if !ok {
		return nil, errors.New("hex inválido")
	}
	return n, nil
}

func mustHex(n *big.Int) string {
	return fmt.Sprintf("%064x", n)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func mustJSONIndent(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func clampRange(min, max *big.Int) (*big.Int, *big.Int, error) {
	N, _ := parseHexBig(secpNHex)
	one := big.NewInt(1)
	if min.Cmp(one) < 0 {
		min = new(big.Int).Set(one)
	}
	if max.Cmp(N) > 0 {
		max = new(big.Int).Set(N)
	}
	if min.Cmp(max) > 0 {
		return nil, nil, errors.New("min > max")
	}
	return min, max, nil
}

func nextSequential(cur, max *big.Int) func() *big.Int {
	n := new(big.Int).Set(cur)
	one := big.NewInt(1)
	return func() *big.Int {
		if n.Cmp(max) > 0 {
			return nil
		}
		out := new(big.Int).Set(n)
		n.Add(n, one)
		return out
	}
}

func randInRange(min, max *big.Int) (*big.Int, error) {
	diff := new(big.Int).Sub(max, min)
	diff.Add(diff, big.NewInt(1))
	r, err := cryptoRand.Int(cryptoRand.Reader, diff)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(min, r), nil
}

func randomGenerator(min, max *big.Int) func() *big.Int {
	var mu sync.Mutex
	return func() *big.Int {
		mu.Lock()
		defer mu.Unlock()
		n, err := randInRange(min, max)
		if err != nil {
			return nil
		}
		return n
	}
}

type workerCfg struct {
	id          int
	gen         func() *big.Int
	targets     TargetSet
	saveAll     bool
	foundFile   string
	progressCh  chan string
	foundCount  *uint64
	checked     *uint64
	stopOnFound bool
}

func worker(ctx context.Context, cfg workerCfg, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n := cfg.gen()
		if n == nil {
			return
		}

		privKey, _ := btcec.PrivKeyFromBytes(n.Bytes())
		comp, uncomp := deriveAddressesFromPriv(privKey)

		atomic.AddUint64(cfg.checked, 1)

		var matched []string
		if _, ok := cfg.targets.Addrs[comp]; ok {
			matched = append(matched, comp)
		}
		if _, ok := cfg.targets.Addrs[uncomp]; ok {
			matched = append(matched, uncomp)
		}

		if len(matched) > 0 {
			atomic.AddUint64(cfg.foundCount, 1)
			colorFound.Printf("\n🎉 [ENCONTRADO!] Chave: %s | Endereços: %v\n", mustHex(n), matched)
			_ = appendFound(cfg.foundFile, FoundKey{
				PrivateKeyHex: mustHex(n),
				Addresses:     matched,
				Compressed:    true,
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			})
			if cfg.stopOnFound {
				return
			}
		} else if cfg.saveAll {
			if err := appendFound(cfg.foundFile, FoundKey{
				PrivateKeyHex: mustHex(n),
				Addresses:     []string{comp, uncomp},
				Compressed:    true,
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				colorError.Printf("Erro ao salvar: %v\n", err)
			}
		}

		select {
		case cfg.progressCh <- mustHex(n):
		default:
		}
	}
}

func runSearch(config *Config) error {
	targets := toTargetSet(config.Addresses)

	// Validar range
	min, err := parseHexBig(config.MinHex)
	if err != nil {
		return fmt.Errorf("min inválido: %v", err)
	}
	max, err := parseHexBig(config.MaxHex)
	if err != nil {
		return fmt.Errorf("max inválido: %v", err)
	}

	// Retomada
	if config.Resume && config.Mode == ModeSequential {
		if ps, err := loadProgress(config.ProgressFile); err == nil && ps.LastCheckedHex != "" {
			if cur, e2 := parseHexBig(ps.LastCheckedHex); e2 == nil && cur.Cmp(max) < 0 {
				min = cur
				colorInfo.Printf("🔄 Retomando busca de: %s\n", ps.LastCheckedHex)
			}
		}
	}

	min, max, err = clampRange(min, max)
	if err != nil {
		return fmt.Errorf("range inválido: %v", err)
	}

	// Preparar diretórios
	_ = os.MkdirAll(filepath.Dir(config.FoundFile), 0o755)

	// Contexto com cancelamento
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigch
		colorInfo.Println("\n🛑 Interrupção recebida, finalizando com segurança...")
		cancel()
	}()

	// Interface de progresso
	spin := spinner.New(spinner.CharSets[14], 120*time.Millisecond)
	spin.Suffix = " 🔍 Buscando chaves..."
	spin.Color("cyan")
	spin.Start()
	defer spin.Stop()

	bar := progressbar.NewOptions64(
		-1,
		progressbar.OptionSetDescription("🔄 Gerando chaves..."),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("keys/s"),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)

	// Métricas
	var checked uint64
	var foundCount uint64
	progressCh := make(chan string, 256)

	start := time.Now()
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastChecked uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cur := atomic.LoadUint64(&checked)
				delta := cur - lastChecked
				lastChecked = cur
				_ = bar.Add64(int64(delta))
			case last := <-progressCh:
				if config.Mode == ModeSequential {
					saveProgress(config.ProgressFile, ProgressState{
						LastCheckedHex: last,
						CountChecked:   fmt.Sprintf("%d", atomic.LoadUint64(&checked)),
						StartedAt:      start.UTC().Format(time.RFC3339),
						Mode:           string(config.Mode),
						MinHex:         config.MinHex,
						MaxHex:         config.MaxHex,
					})
				}
			}
		}
	}()

	// Geradores
	var gen func() *big.Int
	switch config.Mode {
	case ModeSequential:
		gen = nextSequential(new(big.Int).Set(min), max)
	case ModeRandom:
		gen = randomGenerator(min, max)
	}

	// Canal distribuidor
	genCh := make(chan *big.Int, 1024)
	var distWG sync.WaitGroup
	distWG.Add(1)
	go func() {
		defer distWG.Done()
		for {
			select {
			case <-ctx.Done():
				close(genCh)
				return
			default:
				n := gen()
				if n == nil {
					close(genCh)
					return
				}
				genCh <- n
			}
		}
	}()

	genFunc := func() *big.Int {
		n, ok := <-genCh
		if !ok {
			return nil
		}
		return n
	}

	// Workers
	var wg sync.WaitGroup
	wc := config.Workers
	if wc < 1 {
		wc = 1
	}
	if wc > runtime.NumCPU()*4 {
		wc = runtime.NumCPU() * 4
	}

	colorInfo.Printf("\n🚀 Iniciando busca - Modo: %s | Workers: %d\n", config.Mode, wc)

	for i := 0; i < wc; i++ {
		wg.Add(1)
		go worker(ctx, workerCfg{
			id:          i,
			gen:         genFunc,
			targets:     targets,
			saveAll:     config.SaveAll,
			foundFile:   config.FoundFile,
			progressCh:  progressCh,
			foundCount:  &foundCount,
			checked:     &checked,
			stopOnFound: config.StopOnFound,
		}, &wg)
	}

	wg.Wait()
	cancel()
	distWG.Wait()
	_ = bar.Close()
	spin.Stop()

	elapsed := time.Since(start)
	colorFound.Printf("\n✅ Busca finalizada!\n")
	colorInfo.Printf("📊 Estatísticas:\n")
	colorInfo.Printf("   • Chaves verificadas: %d\n", atomic.LoadUint64(&checked))
	colorInfo.Printf("   • Tempo decorrido: %s\n", elapsed.Truncate(time.Millisecond))
	colorInfo.Printf("   • Chaves encontradas: %d\n", atomic.LoadUint64(&foundCount))
	colorInfo.Printf("📁 Arquivos gerados:\n")
	colorInfo.Printf("   • Resultados: %s\n", config.FoundFile)
	colorInfo.Printf("   • Progresso: %s\n", config.ProgressFile)

	return nil
}

func main() {
	rand.Seed(time.Now().UnixNano())

	for {
		printHeader()
		showMainMenu()
		choice := getUserInput("")

		switch choice {
		case "1":
			config, err := quickSetup()
			if err != nil {
				if err.Error() == "voltar" {
					continue
				}
				colorError.Printf("❌ Erro na configuração: %v\n", err)
				continue
			}
			if err := runSearch(config); err != nil {
				colorError.Printf("❌ Erro na busca: %v\n", err)
			}
			return

		case "2":
			config, err := advancedSetup()
			if err != nil {
				colorError.Printf("❌ Erro na configuração: %v\n", err)
				continue
			}
			if err := runSearch(config); err != nil {
				colorError.Printf("❌ Erro na busca: %v\n", err)
			}
			return

		case "3":
			colorError.Println("⚠️  Funcionalidade de carregar configuração não implementada ainda")
			getUserInput("Pressione Enter para continuar...")

		case "4":
			showHelp()

		case "5":
			colorInfo.Println("👋 Obrigado por usar o Enhanced Bitcoin Key Finder!")
			return

		default:
			colorError.Println("❌ Opção inválida. Tente novamente.")
			time.Sleep(1 * time.Second)
		}
	}
}