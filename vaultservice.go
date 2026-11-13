package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type VaultState struct {
	Unlocked   bool               `json:"unlocked"`
	Filename   string             `json:"filename"`
	EntryCount int                `json:"entryCount"`
	Conflict   *VaultConflictInfo `json:"conflict,omitempty"`
}

type VaultConflictInfo struct {
	OriginalPath string `json:"originalPath"`
	LocalPath    string `json:"localPath"`
}

type PasswordOptions struct {
	Length    int  `json:"length"`
	Lowercase bool `json:"lowercase"`
	Uppercase bool `json:"uppercase"`
	Numbers   bool `json:"numbers"`
	Symbols   bool `json:"symbols"`
}

type VaultService struct {
	app *application.App

	mu           sync.Mutex
	path         string
	data         VaultData
	key          []byte
	salt         []byte
	lastHash     [32]byte
	hasBaseline  bool
	lastConflict *VaultConflictInfo

	clipboardTimer      *time.Timer
	lastClipboard       string
	clipboardGeneration uint64
	clipboardRevision   uintptr
	clipboardTracked    bool
}

func NewVaultService() *VaultService {
	return &VaultService{data: VaultData{Categories: []string{}, Entries: []Entry{}}}
}

func (s *VaultService) ChooseVaultToCreate() (string, error) {
	path, err := s.app.Dialog.SaveFile().
		SetMessage("Criar cofre criptografado").
		SetFilename("meu-cofre.vault").
		AddFilter("Cofre do Meu Cofre", "*.vault").
		PromptForSingleSelection()
	if err != nil || path == "" {
		return "", err
	}
	if filepath.Ext(path) == "" {
		path += ".vault"
	}
	return path, nil
}

func (s *VaultService) ChooseVaultToOpen() (string, error) {
	path, err := s.app.Dialog.OpenFile().
		SetTitle("Abrir cofre criptografado").
		AddFilter("Cofres do Meu Cofre", "*.vault;*.vault.backup").
		PromptForSingleSelection()
	if err != nil || path == "" {
		return "", err
	}
	return path, nil
}

func (s *VaultService) CreateVault(path, masterPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path == "" {
		return errors.New("escolha onde salvar o arquivo do cofre")
	}
	if err := validateMasterPassword(masterPassword); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return errors.New("já existe um arquivo nesse local; escolha outro nome")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("verificar destino do cofre: %w", err)
	}

	salt, err := newSalt()
	if err != nil {
		return fmt.Errorf("preparar cofre: %w", err)
	}
	key := deriveVaultKey(masterPassword, salt)
	data := VaultData{Categories: []string{}, Entries: []Entry{}}
	encoded, err := encryptVault(data, key, salt)
	if err != nil {
		wipe(key)
		return err
	}
	if err := atomicWrite(path, encoded); err != nil {
		wipe(key)
		return err
	}
	hash, err := hashFile(path)
	if err != nil {
		wipe(key)
		return fmt.Errorf("verificar cofre criado: %w", err)
	}
	s.lockLocked()
	s.path = path
	s.data = data
	s.key = key
	s.salt = salt
	s.lastHash = hash
	s.hasBaseline = true
	return nil
}

func (s *VaultService) UnlockVault(path, masterPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path == "" || masterPassword == "" {
		return errors.New("informe o arquivo e a senha mestra")
	}
	if len(masterPassword) > 1024 {
		return errors.New("a senha mestra é longa demais")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("abrir arquivo do cofre: %w", err)
	}
	if info.Size() > maxVaultSize {
		return errors.New("o arquivo do cofre é grande demais")
	}
	encoded, err := readVaultFile(path)
	if err != nil {
		return fmt.Errorf("abrir arquivo do cofre: %w", err)
	}
	data, key, err := decryptVault(encoded, masterPassword)
	if err != nil {
		return err
	}
	hash := [32]byte{}
	// Hash exactly the bytes that were successfully decrypted; the file may
	// change again before the first write, which the conflict check will catch.
	hash = hashBytes(encoded)
	s.lockLocked()
	s.path = path
	s.data = data
	s.key = key
	salt, err := vaultSalt(encoded)
	if err != nil {
		s.lockLocked()
		return err
	}
	s.salt = salt
	s.lastHash = hash
	s.hasBaseline = true
	return nil
}

func (s *VaultService) LockVault() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
}

func (s *VaultService) State() VaultState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) == 0 {
		return VaultState{Unlocked: false}
	}
	var conflict *VaultConflictInfo
	if s.lastConflict != nil {
		copy := *s.lastConflict
		conflict = &copy
	}
	return VaultState{Unlocked: true, Filename: filepath.Base(s.path), EntryCount: len(s.data.Entries), Conflict: conflict}
}

func (s *VaultService) ListEntries(search, category string) ([]EntrySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(search))
	entries := make([]EntrySummary, 0, len(s.data.Entries))
	for _, entry := range s.data.Entries {
		if category != "" && entry.Category != category {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(entry.Service+"\n"+entry.Username+"\n"+entry.Notes), query) {
			continue
		}
		entries = append(entries, EntrySummary{
			ID: entry.ID, Service: entry.Service, Username: entry.Username,
			Notes: entry.Notes, Category: entry.Category,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Service) < strings.ToLower(entries[j].Service)
	})
	return entries, nil
}

func (s *VaultService) Categories() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	return append([]string{}, s.data.Categories...), nil
}

func (s *VaultService) GetEntry(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return Entry{}, err
	}
	for _, entry := range s.data.Entries {
		if entry.ID == id {
			return entry, nil
		}
	}
	return Entry{}, errors.New("registro não encontrado")
}

func (s *VaultService) RevealPassword(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return "", err
	}
	for _, entry := range s.data.Entries {
		if entry.ID == id {
			return entry.Password, nil
		}
	}
	return "", errors.New("registro não encontrado")
}

func (s *VaultService) SaveEntry(entry Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	entry.Service = strings.TrimSpace(entry.Service)
	entry.Username = strings.TrimSpace(entry.Username)
	entry.Category = strings.TrimSpace(entry.Category)
	if entry.Service == "" {
		return errors.New("informe o site ou serviço")
	}
	if entry.Password == "" {
		return errors.New("informe ou gere uma senha")
	}
	if err := validateEntry(entry); err != nil {
		return err
	}
	if entry.Category != "" && !contains(s.data.Categories, entry.Category) {
		return errors.New("a categoria selecionada não existe")
	}
	data := cloneVaultData(s.data)
	if entry.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		entry.ID = id
		data.Entries = append(data.Entries, entry)
	} else {
		found := false
		for i := range data.Entries {
			if data.Entries[i].ID == entry.ID {
				data.Entries[i] = entry
				found = true
				break
			}
		}
		if !found {
			return errors.New("registro não encontrado")
		}
	}
	if err := s.saveDataLocked(data); err != nil {
		return err
	}
	return nil
}

func (s *VaultService) DeleteEntry(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	data := cloneVaultData(s.data)
	for i, entry := range data.Entries {
		if entry.ID == id {
			wipeString(&data.Entries[i].Password)
			copy(data.Entries[i:], data.Entries[i+1:])
			data.Entries[len(data.Entries)-1] = Entry{}
			data.Entries = data.Entries[:len(data.Entries)-1]
			return s.saveDataLocked(data)
		}
	}
	return errors.New("registro não encontrado")
}

func (s *VaultService) CreateCategory(name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("informe o nome da categoria")
	}
	if len([]rune(name)) > maxCategoryRunes {
		return nil, errors.New("o nome da categoria deve ter até 32 caracteres")
	}
	for _, current := range s.data.Categories {
		if strings.EqualFold(current, name) {
			return nil, errors.New("essa categoria já existe")
		}
	}
	data := cloneVaultData(s.data)
	data.Categories = append(data.Categories, name)
	sort.Slice(data.Categories, func(i, j int) bool {
		return strings.ToLower(data.Categories[i]) < strings.ToLower(data.Categories[j])
	})
	if err := s.saveDataLocked(data); err != nil {
		return nil, err
	}
	return append([]string{}, data.Categories...), nil
}

func (s *VaultService) DeleteCategory(name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	index := -1
	for i, category := range s.data.Categories {
		if category == name {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, errors.New("categoria não encontrada")
	}
	data := cloneVaultData(s.data)
	data.Categories = append(data.Categories[:index], data.Categories[index+1:]...)
	for i := range data.Entries {
		if data.Entries[i].Category == name {
			data.Entries[i].Category = ""
		}
	}
	if err := s.saveDataLocked(data); err != nil {
		return nil, err
	}
	return append([]string{}, data.Categories...), nil
}

func (s *VaultService) GeneratePassword(options PasswordOptions) (string, error) {
	if options.Length == 0 {
		options.Length = 16
	}
	if options.Length < 8 || options.Length > 128 {
		return "", errors.New("o tamanho deve ficar entre 8 e 128 caracteres")
	}
	var classes []string
	if options.Lowercase {
		classes = append(classes, "abcdefghijkmnopqrstuvwxyz")
	}
	if options.Uppercase {
		classes = append(classes, "ABCDEFGHJKLMNPQRSTUVWXYZ")
	}
	if options.Numbers {
		classes = append(classes, "23456789")
	}
	if options.Symbols {
		classes = append(classes, "!@#$%^&*()-_=+[]{}:,.?/")
	}
	if len(classes) == 0 {
		return "", errors.New("selecione pelo menos um tipo de caractere")
	}
	if options.Length < len(classes) {
		return "", errors.New("o tamanho é menor que a quantidade de tipos selecionados")
	}
	all := strings.Join(classes, "")
	password := make([]byte, 0, options.Length)
	for _, class := range classes {
		index, err := secureIndex(len(class))
		if err != nil {
			return "", err
		}
		password = append(password, class[index])
	}
	for len(password) < options.Length {
		index, err := secureIndex(len(all))
		if err != nil {
			wipe(password)
			return "", err
		}
		password = append(password, all[index])
	}
	for i := len(password) - 1; i > 0; i-- {
		j, err := secureIndex(i + 1)
		if err != nil {
			wipe(password)
			return "", err
		}
		password[i], password[j] = password[j], password[i]
	}
	result := string(password)
	wipe(password)
	return result, nil
}

func (s *VaultService) CopyField(id, field string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return false, err
	}
	var value string
	found := false
	for _, entry := range s.data.Entries {
		if entry.ID != id {
			continue
		}
		found = true
		switch field {
		case "service":
			value = entry.Service
		case "username":
			value = entry.Username
		case "password":
			value = entry.Password
		default:
			return false, errors.New("campo de cópia inválido")
		}
		break
	}
	if !found {
		return false, errors.New("registro não encontrado")
	}
	if value == "" {
		return false, errors.New("não há conteúdo para copiar")
	}
	if !s.app.Clipboard.SetText(value) {
		return false, errors.New("não foi possível copiar para a área de transferência")
	}
	s.lastClipboard = value
	s.clipboardGeneration++
	generation := s.clipboardGeneration
	if s.clipboardTimer != nil {
		s.clipboardTimer.Stop()
	}
	if s.clipboardTracked {
		releaseClipboardRevision(s.clipboardRevision)
	}
	revision, tracked := captureClipboardRevision()
	s.clipboardRevision = revision
	s.clipboardTracked = tracked
	expected := value
	s.clipboardTimer = time.AfterFunc(30*time.Second, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.clipboardGeneration != generation || s.lastClipboard != expected {
			return
		}
		if s.clipboardTracked && s.clipboardRevision == revision {
			if clipboardRevisionMatches(revision) {
				if current, ok := s.app.Clipboard.Text(); ok && current == expected {
					s.app.Clipboard.SetText("")
				}
			}
			releaseClipboardRevision(revision)
			s.clipboardRevision = 0
			s.clipboardTracked = false
		}
		s.lastClipboard = ""
		s.clipboardTimer = nil
	})
	return tracked, nil
}

func (s *VaultService) ChangeMasterPassword(oldPassword, newPassword string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireUnlocked(); err != nil {
		return err
	}
	if len(oldPassword) > 1024 {
		return errors.New("a senha mestra atual é longa demais")
	}
	if err := validateMasterPassword(newPassword); err != nil {
		return err
	}
	oldKey := deriveVaultKey(oldPassword, s.salt)
	valid := subtle.ConstantTimeCompare(oldKey, s.key) == 1
	wipe(oldKey)
	if !valid {
		return errors.New("a senha mestra atual está incorreta")
	}
	newSalt, err := newSalt()
	if err != nil {
		return err
	}
	newKey := deriveVaultKey(newPassword, newSalt)
	if err := s.saveWithMaterialLocked(s.data, newKey, newSalt); err != nil {
		wipe(newKey)
		return err
	}
	wipe(s.key)
	wipe(s.salt)
	s.key = newKey
	s.salt = newSalt
	return nil
}

func (s *VaultService) saveDataLocked(data VaultData) error {
	if err := s.saveWithMaterialLocked(data, s.key, s.salt); err != nil {
		return err
	}
	old := s.data
	s.data = data
	clearVaultData(&old)
	return nil
}

func (s *VaultService) saveWithMaterialLocked(data VaultData, key, salt []byte) error {
	if s.path == "" {
		return errors.New("nenhum cofre está aberto")
	}
	currentBytes, err := readVaultFile(s.path)
	if err != nil {
		return s.preserveConflictLocked(data, key, salt)
	}
	currentHash := hashBytes(currentBytes)
	if !s.hasBaseline || subtle.ConstantTimeCompare(currentHash[:], s.lastHash[:]) != 1 {
		return s.preserveConflictLocked(data, key, salt)
	}
	if err := atomicWrite(s.path+".backup", currentBytes); err != nil {
		return fmt.Errorf("criar cópia de segurança: %w", err)
	}
	encoded, err := encryptVault(data, key, salt)
	if err != nil {
		return err
	}
	if err := atomicWriteIfHashMatches(s.path, currentHash, encoded); err != nil {
		return s.preserveConflictLocked(data, key, salt)
	}
	newHash, err := hashFile(s.path)
	if err != nil {
		return fmt.Errorf("verificar cofre salvo: %w", err)
	}
	if newHash != hashBytes(encoded) {
		return s.preserveConflictLocked(data, key, salt)
	}
	s.lastHash = newHash
	s.lastConflict = nil
	return nil
}

func (s *VaultService) preserveConflictLocked(data VaultData, key, salt []byte) error {
	encoded, encryptErr := encryptVault(data, key, salt)
	if encryptErr != nil {
		return encryptErr
	}
	conflictPath := localConflictPath(s.path)
	if writeErr := atomicWrite(conflictPath, encoded); writeErr != nil {
		return fmt.Errorf("o arquivo foi alterado por outro dispositivo e não foi possível preservar sua cópia local: %w", writeErr)
	}
	s.lastConflict = &VaultConflictInfo{OriginalPath: s.path, LocalPath: conflictPath}
	return fmt.Errorf("o arquivo foi alterado por outro dispositivo; sua versão local foi preservada em %s", filepath.Base(conflictPath))
}

func (s *VaultService) requireUnlocked() error {
	if len(s.key) == 0 || s.path == "" {
		return errors.New("desbloqueie o cofre para continuar")
	}
	return nil
}

func (s *VaultService) lockLocked() {
	s.clipboardGeneration++
	if s.clipboardTimer != nil {
		s.clipboardTimer.Stop()
		s.clipboardTimer = nil
	}
	if s.lastClipboard != "" && s.app != nil && s.clipboardTracked && clipboardRevisionMatches(s.clipboardRevision) {
		if current, ok := s.app.Clipboard.Text(); ok && current == s.lastClipboard {
			s.app.Clipboard.SetText("")
		}
	}
	if s.clipboardTracked {
		releaseClipboardRevision(s.clipboardRevision)
	}
	s.clipboardRevision = 0
	s.clipboardTracked = false
	s.lastClipboard = ""
	wipe(s.key)
	wipe(s.salt)
	clearVaultData(&s.data)
	s.key = nil
	s.salt = nil
	s.path = ""
	s.data = VaultData{Categories: []string{}, Entries: []Entry{}}
	s.lastHash = [32]byte{}
	s.hasBaseline = false
	s.lastConflict = nil
}

func clearVaultData(data *VaultData) {
	for i := range data.Entries {
		wipeString(&data.Entries[i].Password)
		wipeString(&data.Entries[i].Username)
		wipeString(&data.Entries[i].Notes)
	}
}

func validateMasterPassword(password string) error {
	if len([]rune(password)) < 12 {
		return errors.New("use uma senha mestra com pelo menos 12 caracteres; uma frase longa é mais fácil de memorizar")
	}
	if len(password) > 1024 {
		return errors.New("a senha mestra é longa demais")
	}
	return nil
}

func newID() (string, error) {
	var bytes [16]byte
	if _, err := io.ReadFull(rand.Reader, bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func secureIndex(max int) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, fmt.Errorf("gerar valor aleatório: %w", err)
	}
	return int(value.Int64()), nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func wipeString(value *string) {
	// Go strings are immutable and cannot be reliably zeroed in memory. Clear
	// references promptly so the garbage collector can reclaim the old data.
	*value = ""
}
