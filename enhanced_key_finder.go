// enhanced_key_finder.go
// Licença: MIT
// Build: go build -trimpath -ldflags="-s -w" enhanced_key_finder.go

package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
	minHex   = "01"

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

// Utilitários Bitcoin

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

	// prefixo para zeros no início
	for _, b := range input {
		if b == 0x00 {
			out = append(out, alphabet[0])
		} else {
			break
		}
	}

	// inverte
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func checksum(input []byte) []byte {
	first := chainhash.DoubleHashB(input) // SHA256(SHA256())
	return first[:4]
}

func pubKeyToP2PKHAddress(pubkey []byte, compressed bool) string {
	// Versão mainnet P2PKH = 0x00
	sha := chainhash.HashB(pubkey)
	h := ripemd160.New()
	_, _ = h.Write(sha)
	pubKeyHash := h.Sum(nil)
	payload := append([]byte{0x00}, pubKeyHash...)
	full := append(payload, checksum(payload)...)
	return base58Encode(full)
}

func deriveAddressesFromPriv(priv *btcec.PrivateKey) (compressedAddr, uncompressedAddr string) {
	// comprimido
	compressedPub := priv.PubKey().SerializeCompressed()
	// não comprimido
	uncompressedPub := priv.PubKey().SerializeUncompressed()
	return pubKeyToP2PKHAddress(compressedPub, true), pubKeyToP2PKHAddress(uncompressedPub, false)
}

// Entrada de endereços

func loadAddresses(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// tenta {}.address
	var obj InputAddresses
	if err := json.Unmarshal(data, &obj); err == nil && len(obj.Address) > 0 {
		return obj.Address, nil
	}
	// tenta array direto
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

// Progresso

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

// Persistência de resultados

func appendFound(path string, fk FoundKey) error {
	var fr FoundResult
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &fr)
	}
	fr.Results = append(fr.Results, fk)
	return os.WriteFile(path, mustJSONIndent(fr), 0o600)
}

// Conversões e validações

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

// Geradores

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
	// rand criptográfico
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

// Worker de busca

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
	green := color.New(color.FgGreen).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

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
			fmt.Printf("\n[%s] MATCH! pk=%s addrs=%v\n", green("FOUND"), mustHex(n), matched)
			_ = appendFound(cfg.foundFile, FoundKey{
				PrivateKeyHex: mustHex(n),
				Addresses:     matched,
				Compressed:    true, // resultado inclui ambos; mantemos true para marcador principal
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			})
			if cfg.stopOnFound {
				return
			}
		} else if cfg.saveAll {
			// opcionalmente armazena cada tentativa — pode ser pesado
			if err := appendFound(cfg.foundFile, FoundKey{
				PrivateKeyHex: mustHex(n),
				Addresses:     []string{comp, uncomp},
				Compressed:    true,
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
			}); err != nil {
				fmt.Println(red("Falha ao salvar chave gerada:"), err)
			}
		}

		// feedback para progresso (apenas amostragem)
		select {
		case cfg.progressCh <- mustHex(n):
		default:
		}
	}
}

// CLI e orquestração

func main() {
	rand.Seed(time.Now().UnixNano())

	var (
		addressFile   = flag.String("addresses", defaultAddressFile, "Caminho do arquivo address.json")
		minHexIn      = flag.String("min", minHex, "Hex mínimo do range (inclusive)")
		maxHexIn      = flag.String("max", secpNHex, "Hex máximo do range (inclusive)")
		modeIn        = flag.String("mode", string(ModeSequential), "Modo de geração: sequential|random")
		workersIn     = flag.Int("workers", runtime.NumCPU(), "Número de workers (goroutines)")
		saveAll       = flag.Bool("save-all", false, "Salvar todas as chaves geradas (cuidado: pode gerar arquivos grandes)")
		stopOnFound   = flag.Bool("stop-on-found", false, "Parar ao encontrar qualquer match")
		foundPath     = flag.String("out", defaultFoundFile, "Arquivo de saída para chaves encontradas")
		progressPath  = flag.String("progress", defaultProgress, "Arquivo de progresso para retomada")
		resume        = flag.Bool("resume", true, "Retomar de progresso salvo quando possível")
		manualAddress = flag.String("addr", "", "Endereço único informado manualmente (ignora arquivo)")
	)
	flag.Parse()

	// Carregar endereços-alvo
	var targets TargetSet
	if *manualAddress != "" {
		targets = toTargetSet([]string{*manualAddress})
	} else {
		if _, err := os.Stat(*addressFile); err != nil {
			fmt.Printf("Arquivo de endereços não encontrado: %s\n", *addressFile)
			os.Exit(1)
		}
		addrs, err := loadAddresses(*addressFile)
		if err != nil || len(addrs) == 0 {
			fmt.Println("Falha ao carregar endereços alvo:", err)
			os.Exit(1)
		}
		targets = toTargetSet(addrs)
	}

	// Validar e ajustar range
	min, err := parseHexBig(*minHexIn)
	if err != nil {
		fmt.Println("Min inválido:", err)
		os.Exit(1)
	}
	max, err := parseHexBig(*maxHexIn)
	if err != nil {
		fmt.Println("Max inválido:", err)
		os.Exit(1)
	}

	// Retomada (apenas para modo sequencial)
	if *resume && *modeIn == string(ModeSequential) {
		if ps, err := loadProgress(*progressPath); err == nil && ps.LastCheckedHex != "" && ps.Mode == string(ModeSequential) && ps.MinHex == strings.ToLower(*minHexIn) && ps.MaxHex == strings.ToLower(*maxHexIn) {
			if cur, e2 := parseHexBig(ps.LastCheckedHex); e2 == nil && cur.Cmp(max) < 0 {
				min = cur
				color.New(color.FgYellow).Printf("Retomando de %s\n", ps.LastCheckedHex)
			}
		}
	}

	min, max, err = clampRange(min, max)
	if err != nil {
		fmt.Println("Range inválido:", err)
		os.Exit(1)
	}

	// Modo
	var mode Mode
	switch strings.ToLower(*modeIn) {
	case string(ModeSequential):
		mode = ModeSequential
	case string(ModeRandom):
		mode = ModeRandom
	default:
		fmt.Println("Modo inválido:", *modeIn)
		os.Exit(1)
	}

	// Preparar saída
	_ = os.MkdirAll(filepath.Dir(*foundPath), 0o755)

	// Contexto com cancelamento (Ctrl+C)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigch
		color.New(color.FgYellow).Println("\nInterrupção recebida, finalizando com segurança...")
		cancel()
	}()

	// UI: spinner e barra de progresso
	spin := spinner.New(spinner.CharSets[14], 120*time.Millisecond)
	spin.Suffix = " Buscando chaves..."
	spin.Color("cyan")
	spin.Start()
	defer spin.Stop()

	bar := progressbar.NewOptions64(
		-1, // indeterminado
		progressbar.OptionSetDescription("Gerando..."),
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
				// grava progresso periódico (somente sequencial)
				if mode == ModeSequential {
					saveProgress(*progressPath, ProgressState{
						LastCheckedHex: last,
						CountChecked:   fmt.Sprintf("%d", atomic.LoadUint64(&checked)),
						StartedAt:      start.UTC().Format(time.RFC3339),
						Mode:           string(mode),
						MinHex:         strings.ToLower(*minHexIn),
						MaxHex:         strings.ToLower(*maxHexIn),
					})
				}
			}
		}
	}()

	// Geradores
	var gen func() *big.Int
	switch mode {
	case ModeSequential:
		gen = nextSequential(new(big.Int).Set(min), max)
	case ModeRandom:
		gen = randomGenerator(min, max)
	}

	// Distribuidor para workers
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

	// Wrap para gerar por canal
	genFunc := func() *big.Int {
		n, ok := <-genCh
		if !ok {
			return nil
		}
		return n
	}

	// Workers
	var wg sync.WaitGroup
	wc := *workersIn
	if wc < 1 {
		wc = 1
	}
	if wc > runtime.NumCPU()*4 {
		// limite de sanidade
		wc = runtime.NumCPU() * 4
	}

	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	fmt.Printf("%s Modo: %s | Workers: %d | Range: [%s, %s]\n",
		cyan("Config:"), string(mode), wc, strings.ToLower(*minHexIn), strings.ToLower(*maxHexIn))

	for i := 0; i < wc; i++ {
		wg.Add(1)
		go worker(ctx, workerCfg{
			id:          i,
			gen:         genFunc,
			targets:     targets,
			saveAll:     *saveAll,
			foundFile:   *foundPath,
			progressCh:  progressCh,
			foundCount:  &foundCount,
			checked:     &checked,
			stopOnFound: *stopOnFound,
		}, &wg)
	}

	wg.Wait()
	cancel()
	distWG.Wait()
	_ = bar.Close()
	spin.Stop()

	elapsed := time.Since(start)
	yellow := color.New(color.FgYellow).SprintFunc()
	fmt.Printf("%s Finalizado. Verificadas %d chaves em %s. Encontradas: %d\n",
		green("OK:"), atomic.LoadUint64(&checked), elapsed.Truncate(time.Millisecond), atomic.LoadUint64(&foundCount))
	fmt.Printf("%s Resultados em: %s | Progresso: %s\n", yellow("Saída:"), *foundPath, *progressPath)
}
