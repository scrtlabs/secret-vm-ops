package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HTTP client with 30s timeout for all requests
var httpClient = &http.Client{Timeout: 10 * time.Second}

// HKDF salt used in key derivation
var hkdfSalt = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x4b, 0xea, 0xd8, 0xdf, 0x69, 0x99,
	0x08, 0x52, 0xc2, 0x02, 0xdb, 0x0e, 0x00, 0x97,
	0xc1, 0xa1, 0x2e, 0xa6, 0x37, 0xd7, 0xe9, 0x6d,
}

// Hardcoded default endpoints
var defaultEndpoints = []string{
	"https://lcd.secret.tactus.starshell.net",
	"https://rpc.ankr.com/http/scrt_cosmos",
	"https://1rpc.io/scrt-lcd",
	"https://secretnetwork-api.lavenderfive.com:443",
	"https://rest-secret.01node.com",
}

// Final list of endpoints (defaults + CLI extras)
var endpoints []string

// WASMContext holds key context and nonce
type WASMContext struct {
	cliContext map[string]string
	nonce      []byte
}

func NewWASMContext(cliContext map[string]string) (*WASMContext, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return &WASMContext{cliContext: cliContext, nonce: nonce}, nil
}

// Read or generate Curve25519 keypair
func (w *WASMContext) getTxSenderKeyPair() ([]byte, []byte, error) {
	path := filepath.Join(w.cliContext["home_dir"], "id_tx_io.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		var pub [32]byte
		curve25519.ScalarBaseMult(&pub, (*[32]byte)(priv))
		kp := map[string]string{"private": hex.EncodeToString(priv), "public": hex.EncodeToString(pub[:])}
		data, _ := json.Marshal(kp)
		ioutil.WriteFile(path, data, 0600)
		return priv, pub[:], nil
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key pair: %w", err)
	}
	kp := map[string]string{}
	json.Unmarshal(data, &kp)
	priv, _ := hex.DecodeString(kp["private"])
	pub, _ := hex.DecodeString(kp["public"])
	return priv, pub, nil
}

// perform GET with timeout
func httpGet(url string) (*http.Response, error) {
	return httpClient.Get(url)
}

// Fetch consensus IO pub key via a single base URL
func fetchConsensusIOPubKeyVia(base string) ([]byte, error) {
	url := fmt.Sprintf("%s/registration/v1beta1/tx-key", base)
	resp, err := httpGet(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus IO key: %w", err)
	}
	defer resp.Body.Close()
	var res map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode consensus IO response: %w", err)
	}
	return base64.StdEncoding.DecodeString(res["key"])
}

// Derive AES-SIV key via HKDF per base
func deriveTxKeyFromBase(priv, nonce []byte, base string) ([]byte, error) {
	consPub, err := fetchConsensusIOPubKeyVia(base)
	if err != nil {
		return nil, err
	}
	var shared [32]byte
	curve25519.ScalarMult(&shared, (*[32]byte)(priv), (*[32]byte)(consPub))
	hk := hkdf.New(sha256.New, append(shared[:], nonce...), hkdfSalt, nil)
	key := make([]byte, 32)
	if _, err := hk.Read(key); err != nil {
		return nil, fmt.Errorf("hkdf read failed: %w", err)
	}
	return key, nil
}

// Encrypt with context and base
func encryptWithBase(ctx *WASMContext, base string, plaintext []byte) ([]byte, error) {
	priv, pub, err := ctx.getTxSenderKeyPair()
	if err != nil {
		return nil, err
	}
	key, err := deriveTxKeyFromBase(priv, ctx.nonce, base)
	if err != nil {
		return nil, err
	}
	siv, err := miscreant.NewAESCMACSIV(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-SIV: %w", err)
	}
	ct, err := siv.Seal(nil, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("seal failed: %w", err)
	}
	return append(append(ctx.nonce, pub...), ct...), nil
}

// / decryptWithBase decrypts a server response (SIV-tag∥ciphertext) using
// the shared key derived from ctx.nonce exactly as in the original.
func decryptWithBase(ctx *WASMContext, base string, ciphertext []byte) ([]byte, error) {
	// 1) Load/generate our keypair
	priv, _, err := ctx.getTxSenderKeyPair()
	if err != nil {
		return nil, err
	}

	// 2) Derive the AES-SIV key using HKDF(shared_secret || nonce)
	sivKey, err := deriveTxKeyFromBase(priv, ctx.nonce, base)
	if err != nil {
		return nil, fmt.Errorf("failed to derive SIV key: %w", err)
	}

	// 3) Instantiate AES-SIV
	siv, err := miscreant.NewAESCMACSIV(sivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-SIV: %w", err)
	}

	// 4) Open the raw SIV output (tag∥ciphertext), no associated data
	plaintext, err := siv.Open(nil, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return plaintext, nil
}

// Fetch code hash from a single base URL
func fetchCodeHashVia(base, addr string) (string, error) {
	url := fmt.Sprintf("%s/compute/v1beta1/code_hash/by_contract_address/%s", base, addr)
	resp, err := httpGet(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch code hash: %w", err)
	}
	defer resp.Body.Close()
	var r struct {
		CodeHash string `json:"code_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("decode code hash failed: %w", err)
	}
	return r.CodeHash, nil
}

// TryQueryContract attempts a full request/response cycle against one base URL:
//  1. fetches the on-chain code hash
//  2. initializes a new WASMContext (fresh nonce)
//  3. serializes and encrypts codeHash + JSON(query)
//  4. sends the HTTP GET with the encrypted payload
//  5. parses the JSON response
//  6. decrypts the "data" field if present
//  7. otherwise tries to extract and decrypt an "encrypted: …" message
//  8. returns the decrypted map or an error
func TryQueryContract(base, contractAddr string, query map[string]interface{}) (map[string]interface{}, error) {
	// 1) fetch code hash
	codeHash, err := fetchCodeHashVia(base, contractAddr)
	if err != nil {
		return nil, err
	}

	// 2) build context + nonce
	ctx, err := NewWASMContext(map[string]string{"home_dir": os.Getenv("HOME")})
	if err != nil {
		return nil, err
	}

	// 3) prepare plaintext = codeHash + serialized query
	payload := []byte(codeHash + mustJSON(query))

	// 4) encrypt under AES-SIV (prefixing nonce||pubkey internally)
	enc, err := encryptWithBase(ctx, base, payload)
	if err != nil {
		return nil, err
	}
	qry := base64.URLEncoding.EncodeToString(enc)

	// 5) send HTTP GET
	url := fmt.Sprintf("%s/compute/v1beta1/query/%s?query=%s", base, contractAddr, qry)
	resp, err := httpGet(url)
	if err != nil {
		return nil, fmt.Errorf("query request failed: %w", err)
	}
	defer resp.Body.Close()

	// 6) parse JSON
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var respMap map[string]interface{}
	if err := json.Unmarshal(body, &respMap); err != nil {
		return nil, err
	}

	// 7) handle “data” field: base64→decrypt→base64→JSON
	if encB64, ok := respMap["data"].(string); ok {
		// A) base64 decode ciphertext
		cipherBytes, err := base64.StdEncoding.DecodeString(encB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode data field: %w", err)
		}
		// B) decrypt SIV
		decryptedB64, err := decryptWithBase(ctx, base, cipherBytes)
		if err != nil {
			return nil, err
		}
		// C) decryptedB64 is base64(JSON) → decode
		rawJSON, err := base64.StdEncoding.DecodeString(string(decryptedB64))
		if err != nil {
			return nil, fmt.Errorf("failed to decode decrypted JSON: %w", err)
		}
		// D) unmarshal into map
		var result map[string]interface{}
		if err := json.Unmarshal(rawJSON, &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON payload: %w", err)
		}
		return result, nil
	} else if msg, ok := respMap["message"].(string); ok { 
		// 8) fallback: check for "encrypted: ..." in message
		if strings.Contains(msg, "encrypted: ") {
			parts := strings.SplitN(strings.TrimPrefix(msg, "encrypted: "), ": ", 2)
			if len(parts) > 0 {
				encStr := strings.TrimSpace(parts[0])
				if decodedResp, err := base64.StdEncoding.DecodeString(encStr); err == nil {
					if decrypted, err2 := decryptWithBase(ctx, base, decodedResp); err2 == nil {
						return map[string]interface{}{"message": string(decrypted)}, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("message: %s", msg)
	}

	// 9) nothing decryptable found
	return nil, fmt.Errorf("response data not found")
}

// QueryContract tries all endpoints in sequence, returns first error if all fail
func QueryContract(contractAddr string, query map[string]interface{}) (map[string]interface{}, error) {
	var firstErr error
	for _, base := range endpoints {
		res, err := TryQueryContract(base, contractAddr, query)
		if err == nil {
			return res, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, fmt.Errorf("all endpoints failed: %w", firstErr)
}

// helpers
func mustJSON(v interface{}) string { b, _ := json.Marshal(v); return string(b) }
func mustParseJSON(b []byte) map[string]interface{} {
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	return m
}
func toInterfaceSlice(b []byte) []interface{} {
	s := make([]interface{}, len(b))
	for i, v := range b {
		s[i] = v
	}
	return s
}

func main() {
	// detect command index
	i := 1
	for ; i < len(os.Args); i++ {
		if os.Args[i] == "get_secret_key" || os.Args[i] == "get_env_by_image" || os.Args[i] == "get_secret_key_by_image" {
			break
		}
	}
	if i == len(os.Args) {
		fmt.Println("Usage: go run kms_query.go [<extra_endpoint>...] get_secret_key service_id quoteHex collateralHex")
		fmt.Println("       go run kms_query.go [<extra_endpoint>...] get_env_by_image quoteHex collateralHex")
		fmt.Println("       go run kms_query.go [<extra_endpoint>...] get_secret_key_by_image quoteHex collateralHex")
		os.Exit(1)
	}
	// any CLI-provided endpoints go at the front
	if i > 1 {
		endpoints = append(endpoints, os.Args[1:i]...)
	}
	// then append the built-in defaults
	endpoints = append(endpoints, defaultEndpoints...)

	cmd := os.Args[i]
	args := os.Args[i+1:]
	contractAddr := "secret1w500qy39wtwaghwn9e5qu5sx23k2xtjfkj20as"
	var query map[string]interface{}

	switch cmd {
	case "get_secret_key":
		if len(args) != 3 {
			fmt.Println("Usage: get_secret_key service_id quoteHex collateralHex")
			os.Exit(1)
		}
		id, _ := strconv.Atoi(args[0])
		q, _ := hex.DecodeString(args[1])
		c, _ := hex.DecodeString(args[2])
		query = map[string]interface{}{"get_secret_key": map[string]interface{}{"service_id": id, "quote": toInterfaceSlice(q), "collateral": toInterfaceSlice(c)}}

	case "get_env_by_image":
		if len(args) != 2 {
			fmt.Println("Usage: get_env_by_image quoteHex collateralHex")
			os.Exit(1)
		}
		q, _ := hex.DecodeString(args[0])
		c, _ := hex.DecodeString(args[1])
		query = map[string]interface{}{"get_env_by_image": map[string]interface{}{"quote": toInterfaceSlice(q), "collateral": toInterfaceSlice(c)}}

	case "get_secret_key_by_image":
		if len(args) != 2 {
			fmt.Println("Usage: get_secret_key_by_image quoteHex collateralHex")
			os.Exit(1)
		}
		q, _ := hex.DecodeString(args[0])
		c, _ := hex.DecodeString(args[1])
		query = map[string]interface{}{"get_secret_key_by_image": map[string]interface{}{"quote": toInterfaceSlice(q), "collateral": toInterfaceSlice(c)}}

	default:
		fmt.Println("Unknown command", cmd)
		os.Exit(1)
	}

	res, err := QueryContract(contractAddr, query)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}
