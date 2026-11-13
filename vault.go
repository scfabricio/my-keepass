package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	vaultFormat      = "meu-cofre"
	vaultVersion     = 1
	argonTime        = 3
	argonMemory      = 64 * 1024 // KiB (64 MiB)
	argonThreads     = 4
	keySize          = 32
	maxVaultSize     = 16 << 20
	maxServiceRunes  = 160
	maxUsernameRunes = 320
	maxPasswordBytes = 4096
	maxNotesRunes    = 4000
	maxCategoryRunes = 32
)

var vaultAAD = []byte("meu-cofre:v1")

type Entry struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
	Notes    string `json:"notes"`
	Category string `json:"category"`
}

type EntrySummary struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Notes    string `json:"notes"`
	Category string `json:"category"`
}

type VaultData struct {
	Categories []string `json:"categories"`
	Entries    []Entry  `json:"entries"`
}

func cloneVaultData(data VaultData) VaultData {
	return VaultData{
		Categories: append([]string{}, data.Categories...),
		Entries:    append([]Entry{}, data.Entries...),
	}
}

func validateEntry(entry Entry) error {
	if utf8.RuneCountInString(entry.Service) > maxServiceRunes {
		return errors.New("o site ou serviço deve ter até 160 caracteres")
	}
	if utf8.RuneCountInString(entry.Username) > maxUsernameRunes {
		return errors.New("o usuário deve ter até 320 caracteres")
	}
	if len(entry.Password) > maxPasswordBytes {
		return errors.New("a senha deve ter até 4096 bytes")
	}
	if utf8.RuneCountInString(entry.Notes) > maxNotesRunes {
		return errors.New("as notas devem ter até 4000 caracteres")
	}
	if utf8.RuneCountInString(entry.Category) > maxCategoryRunes {
		return errors.New("a categoria deve ter até 32 caracteres")
	}
	return nil
}

type VaultHeader struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	KDF     struct {
		Name    string `json:"name"`
		Time    uint32 `json:"time"`
		Memory  uint32 `json:"memory_kib"`
		Threads uint8  `json:"threads"`
		Salt    string `json:"salt"`
	} `json:"kdf"`
	Cipher struct {
		Name       string `json:"name"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	} `json:"cipher"`
}

func newSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func deriveVaultKey(password string, salt []byte) []byte {
	passwordBytes := []byte(password)
	defer wipe(passwordBytes)
	return argon2.IDKey(passwordBytes, salt, argonTime, argonMemory, argonThreads, keySize)
}

func encryptVault(data VaultData, key, salt []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, errors.New("a chave do cofre tem um tamanho inválido")
	}
	if len(salt) != 16 {
		return nil, errors.New("o salt do cofre tem um tamanho inválido")
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serializar cofre: %w", err)
	}
	defer wipe(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("preparar cifra: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("preparar autenticação: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("gerar nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, vaultAAD)

	var envelope VaultHeader
	envelope.Format = vaultFormat
	envelope.Version = vaultVersion
	envelope.KDF.Name = "argon2id"
	envelope.KDF.Time = argonTime
	envelope.KDF.Memory = argonMemory
	envelope.KDF.Threads = argonThreads
	envelope.KDF.Salt = base64.RawStdEncoding.EncodeToString(salt)
	envelope.Cipher.Name = "aes-256-gcm"
	envelope.Cipher.Nonce = base64.RawStdEncoding.EncodeToString(nonce)
	envelope.Cipher.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)

	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializar arquivo do cofre: %w", err)
	}
	if len(encoded) > maxVaultSize {
		return nil, errors.New("o cofre excede o limite de 16 MiB")
	}
	return encoded, nil
}

func decryptVault(encoded []byte, password string) (VaultData, []byte, error) {
	var empty VaultData
	if len(encoded) == 0 || len(encoded) > maxVaultSize {
		return empty, nil, errors.New("o arquivo do cofre está vazio ou é grande demais")
	}
	if password == "" || len(password) > 1024 {
		return empty, nil, errors.New("a senha mestra está vazia ou é longa demais")
	}

	var envelope VaultHeader
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return empty, nil, errors.New("o arquivo não tem um formato de cofre válido")
	}
	if envelope.Format != vaultFormat || envelope.Version != vaultVersion {
		return empty, nil, errors.New("formato ou versão do cofre não são compatíveis")
	}
	// Only accept the parameters written by this version. This prevents a
	// modified header from forcing an excessive Argon2 allocation on unlock.
	if envelope.KDF.Name != "argon2id" || envelope.KDF.Time != argonTime || envelope.KDF.Memory != argonMemory || envelope.KDF.Threads != argonThreads {
		return empty, nil, errors.New("parâmetros de derivação do cofre não são compatíveis")
	}
	if envelope.Cipher.Name != "aes-256-gcm" {
		return empty, nil, errors.New("cifra do cofre não é compatível")
	}

	salt, err := base64.RawStdEncoding.DecodeString(envelope.KDF.Salt)
	if err != nil || len(salt) != 16 {
		return empty, nil, errors.New("o arquivo do cofre contém um salt inválido")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Cipher.Nonce)
	if err != nil {
		return empty, nil, errors.New("o arquivo do cofre contém um nonce inválido")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(envelope.Cipher.Ciphertext)
	if err != nil {
		return empty, nil, errors.New("o arquivo do cofre contém dados inválidos")
	}

	key := deriveVaultKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		wipe(key)
		return empty, nil, fmt.Errorf("preparar cifra: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		wipe(key)
		return empty, nil, fmt.Errorf("preparar autenticação: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		wipe(key)
		return empty, nil, errors.New("o arquivo do cofre contém um nonce inválido")
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, vaultAAD)
	if err != nil {
		wipe(key)
		return empty, nil, errors.New("senha mestra incorreta ou cofre danificado")
	}
	defer wipe(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		wipe(key)
		return empty, nil, errors.New("o conteúdo descriptografado do cofre não é válido")
	}
	if data.Categories == nil {
		data.Categories = []string{}
	}
	if data.Entries == nil {
		data.Entries = []Entry{}
	}
	return data, key, nil
}

func atomicWrite(path string, contents []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".meu-cofre-*.tmp")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("proteger arquivo temporário: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return fmt.Errorf("gravar cofre: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sincronizar cofre: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("fechar arquivo temporário: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("substituir arquivo do cofre: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

// atomicWriteIfHashMatches avoids replacing a file that changed while the
// replacement was being prepared. Filesystem sync clients do not provide a
// compare-and-swap primitive, so callers still verify the result afterward.
func atomicWriteIfHashMatches(path string, expected [32]byte, contents []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".meu-cofre-*.tmp")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("proteger arquivo temporário: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return fmt.Errorf("gravar cofre: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sincronizar cofre: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("fechar arquivo temporário: %w", err)
	}
	current, err := hashFile(path)
	if err != nil || current != expected {
		return errors.New("o arquivo do cofre mudou durante a gravação")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("substituir arquivo do cofre: %w", err)
	}
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func readVaultFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxVaultSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxVaultSize {
		return nil, errors.New("o arquivo do cofre é grande demais")
	}
	return data, nil
}

func hashFile(path string) ([32]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func hashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func vaultSalt(encoded []byte) ([]byte, error) {
	var envelope VaultHeader
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, errors.New("não foi possível ler o salt do cofre")
	}
	salt, err := base64.RawStdEncoding.DecodeString(envelope.KDF.Salt)
	if err != nil || len(salt) != 16 {
		return nil, errors.New("o arquivo do cofre contém um salt inválido")
	}
	return salt, nil
}

func localConflictPath(path string) string {
	stamp := time.Now().UTC().Format("20060102-150405.000000000")
	id, err := newID()
	if err != nil {
		id = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	base := strings.TrimSuffix(path, filepath.Ext(path))
	return fmt.Sprintf("%s.conflito-local-%s-%s.vault", base, stamp, id)
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
