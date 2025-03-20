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
	"strings"

	"github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HKDF salt used in key derivation
var hkdfSalt = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x4b, 0xea, 0xd8, 0xdf, 0x69, 0x99,
	0x08, 0x52, 0xc2, 0x02, 0xdb, 0x0e, 0x00, 0x97,
	0xc1, 0xa1, 0x2e, 0xa6, 0x37, 0xd7, 0xe9, 0x6d,
}

type WASMContext struct {
	cliContext      map[string]string
	testKeyPairPath string
	nonce           []byte
}

func NewWASMContext(cliContext map[string]string) (*WASMContext, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &WASMContext{
		cliContext: cliContext,
		nonce:      nonce,
	}, nil
}

func (w *WASMContext) getTxSenderKeyPair() ([]byte, []byte, error) {
	keyPairFilePath := w.testKeyPairPath
	if keyPairFilePath == "" {
		keyPairFilePath = filepath.Join(w.cliContext["home_dir"], "id_tx_io.json")
	}

	if _, err := os.Stat(keyPairFilePath); os.IsNotExist(err) {
		privKey := make([]byte, 32)
		if _, err := rand.Read(privKey); err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
		}

		var pubKey [32]byte
		curve25519.ScalarBaseMult(&pubKey, (*[32]byte)(privKey))

		keyPair := map[string]string{
			"private": hex.EncodeToString(privKey),
			"public":  hex.EncodeToString(pubKey[:]),
		}

		jsonData, err := json.Marshal(keyPair)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal key pair: %w", err)
		}

		if err := ioutil.WriteFile(keyPairFilePath, jsonData, 0600); err != nil {
			return nil, nil, fmt.Errorf("failed to write key pair file: %w", err)
		}

		return privKey, pubKey[:], nil
	}

	data, err := ioutil.ReadFile(keyPairFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key pair file: %w", err)
	}

	var keyPair map[string]string
	if err := json.Unmarshal(data, &keyPair); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal key pair: %w", err)
	}

	privKey, err := hex.DecodeString(keyPair["private"])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	pubKey, err := hex.DecodeString(keyPair["public"])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return privKey, pubKey, nil
}

func (w *WASMContext) getConsensusIOPubKey() ([]byte, error) {
	resp, err := http.Get("http://51.8.118.178:1317/registration/v1beta1/tx-key")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus IO public key: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode consensus IO response: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(result["key"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode consensus IO key: %w", err)
	}

	return key, nil
}

func (w *WASMContext) getTxEncryptionKey(txSenderPrivKey []byte) ([]byte, error) {
	consensusIOPubKey, err := w.getConsensusIOPubKey()
	if err != nil {
		return nil, err
	}

	var shared [32]byte
	curve25519.ScalarMult(&shared, (*[32]byte)(txSenderPrivKey), (*[32]byte)(consensusIOPubKey))

	hash := sha256.New
	hkdf := hkdf.New(hash, append(shared[:], w.nonce...), hkdfSalt, nil)

	key := make([]byte, 32)
	if _, err := hkdf.Read(key); err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}

	return key, nil
}

func (w *WASMContext) Encrypt(plaintext []byte) ([]byte, error) {
	txSenderPrivKey, txSenderPubKey, err := w.getTxSenderKeyPair()
	if err != nil {
		return nil, err
	}

	txEncryptionKey, err := w.getTxEncryptionKey(txSenderPrivKey)
	if err != nil {
		return nil, err
	}

	siv, err := miscreant.NewAESCMACSIV(txEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-SIV: %w", err)
	}

	ciphertext := make([]byte, 0)
	ciphertext, err = siv.Seal(ciphertext, plaintext, []byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	result := append(w.nonce, txSenderPubKey...)
	result = append(result, ciphertext...)

	return result, nil
}

func (w *WASMContext) Decrypt(ciphertext []byte) ([]byte, error) {
	txSenderPrivKey, _, err := w.getTxSenderKeyPair()
	if err != nil {
		return nil, err
	}

	txEncryptionKey, err := w.getTxEncryptionKey(txSenderPrivKey)
	if err != nil {
		return nil, err
	}

	siv, err := miscreant.NewAESCMACSIV(txEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-SIV: %w", err)
	}

	plaintext := make([]byte, 0)
	plaintext, err = siv.Open(plaintext, ciphertext, []byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func fetchCodeHash(contractAddress string) (string, error) {
	// API endpoint to get the code hash by contract address
	url := fmt.Sprintf("http://51.8.118.178:1317/compute/v1beta1/code_hash/by_contract_address/%s", contractAddress)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch code hash: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var result struct {
		CodeHash string `json:"code_hash"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", fmt.Errorf("failed to decode code hash response: %w", err)
	}

	return result.CodeHash, nil
}

func QueryContract(contractAddress string, query map[string]interface{}) (map[string]interface{}, error) {
	// Fetch the code hash dynamically
	codeHash, err := fetchCodeHash(contractAddress)
	if err != nil {
		return nil, err
	}

	cliContext := map[string]string{"home_dir": ""}
	context, err := NewWASMContext(cliContext)
	if err != nil {
		return nil, err
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	textQuery := codeHash + string(queryJSON)
	encryptedData, err := context.Encrypt([]byte(textQuery))
	if err != nil {
		return nil, err
	}

	encodedData := base64.URLEncoding.EncodeToString(encryptedData)
	url := fmt.Sprintf("http://51.8.118.178:1317/compute/v1beta1/query/%s?query=%s", contractAddress, encodedData)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query contract: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var responseData map[string]interface{}
	if err := json.Unmarshal(responseBody, &responseData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if encodedResponse, ok := responseData["data"].(string); ok {
		decodedResponse, err := base64.StdEncoding.DecodeString(encodedResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to decode response data: %w", err)
		}

		decryptedData, err := context.Decrypt(decodedResponse)
		if err != nil {
			return nil, err
		}

		decodedData, err := base64.StdEncoding.DecodeString(string(decryptedData))
		if err != nil {
			return nil, fmt.Errorf("failed to decode decrypted data: %w", err)
		}

		fmt.Printf("Query result: %s\n", string(decodedData))

		var result map[string]interface{}
		if err := json.Unmarshal(decodedData, &result); err != nil {
			return nil, fmt.Errorf("failed to parse decrypted data: %w", err)
		}

		return result, nil
	} else if message, ok := responseData["message"].(string); ok {
		if strings.Contains(message, "encrypted: ") {
			encryptedMessage := strings.TrimPrefix(message, "encrypted: ")
			parts := strings.Split(encryptedMessage, ": ")
			if len(parts) > 0 {
				encryptedData := strings.TrimSpace(parts[0])
				decodedResponse, err := base64.StdEncoding.DecodeString(encryptedData)
				if err == nil {
					decryptedData, err := context.Decrypt(decodedResponse)
					if err == nil {
						fmt.Printf("Decrypted message: %s\n", string(decryptedData))
						var result map[string]interface{}
						result = make(map[string]interface{})
						result["message"] = string(decryptedData)
						return result, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("response data not found")
}

func readFile(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return hex.DecodeString(string(data))
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: service_id hex_encoded(quote) hex_encoded(collateral)")
		os.Exit(1)
	}

	serviceID := 0
	quoteBytes, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Printf("Failed to decode quote: %s\n", err)
		os.Exit(1)
	}

	collateralBytes, err := hex.DecodeString(os.Args[3])
	if err != nil {
		fmt.Printf("Failed to decode collateral: %s\n", err)
		os.Exit(1)
	}

	quote := make([]interface{}, len(quoteBytes))
	for i, b := range quoteBytes {
		quote[i] = b
	}

	collateral := make([]interface{}, len(collateralBytes))
	for i, b := range collateralBytes {
		collateral[i] = b
	}

	contractAddress := "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu"
	query := map[string]interface{}{
		"get_secret_key": map[string]interface{}{
			"service_id": serviceID,
			"quote":      quote,
			"collateral": collateral,
		},
	}

	result, err := QueryContract(contractAddress, query)
	if err != nil {
		fmt.Printf("Failed to query contract: %s\n", err)
		os.Exit(1)
	}

	encryptedKey, ok := result["encrypted_secret_key"].(string)
	if !ok {
		fmt.Println("Missing 'encrypted_secret_key' in response")
		os.Exit(1)
	}
	encryptionPubKey, ok := result["encryption_pub_key"].(string)
	if !ok {
		fmt.Println("Missing 'encryption_pub_key' in response")
		os.Exit(1)
	}

	fmt.Println(encryptedKey)
	fmt.Println(encryptionPubKey)
}
