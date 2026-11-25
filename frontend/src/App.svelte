<script lang="ts">
  import { onMount } from 'svelte';
  import * as Vault from '../bindings/my-keepass/vaultservice';
  import type { Entry, EntrySummary, PasswordOptions } from '../bindings/my-keepass/models';

  type Screen = 'welcome' | 'create' | 'unlock' | 'vault';
  type NoticeKind = 'success' | 'error';
  type ConflictInfo = { originalPath: string; localPath: string };
  type DeleteConfirmation = { kind: 'entry'; entry: EntrySummary } | { kind: 'category'; name: string };

  let screen = $state<Screen>('welcome');
  let vaultPath = $state('');
  let filename = $state('');
  let entries = $state<EntrySummary[]>([]);
  let categories = $state<string[]>([]);
  let search = $state('');
  let activeCategory = $state('');
  let notice = $state('');
  let noticeKind = $state<NoticeKind>('success');
  let busy = $state(false);
  let conflict = $state<ConflictInfo | null>(null);
  let deleteConfirmation = $state<DeleteConfirmation | null>(null);

  let unlockPassword = $state('');
  let newMasterPassword = $state('');
  let confirmMasterPassword = $state('');
  let showMasterPassword = $state(false);

  let editorOpen = $state(false);
  let editing = $state(false);
  let form = $state<Entry>(emptyEntry());
  let showEntryPassword = $state(false);
  let passwordOptions = $state<PasswordOptions>({
    length: 16,
    lowercase: true,
    uppercase: true,
    numbers: true,
    symbols: true,
  });
  let revealed = $state<Record<string, string>>({});

  let categoryInputOpen = $state(false);
  let newCategoryName = $state('');
  let changePasswordOpen = $state(false);
  let currentMasterPassword = $state('');
  let replacementMasterPassword = $state('');
  let confirmReplacementPassword = $state('');
  let toastTimer: ReturnType<typeof setTimeout>;
  let refreshGeneration = 0;
  let shortcutModifier = $state('Ctrl+');

  onMount(() => {
    if (navigator.platform.includes('Mac')) shortcutModifier = '⌘ ';
    const onShortcut = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        if (conflict) conflict = null;
        else if (deleteConfirmation && !busy) deleteConfirmation = null;
        else if (changePasswordOpen) closeChangePassword();
        else if (editorOpen) closeEntryEditor();
        else if (categoryInputOpen) categoryInputOpen = false;
        else return;
        event.preventDefault();
        return;
      }
      if (event.key === 'Tab') {
        const dialog = document.querySelector<HTMLElement>('.modal-backdrop [role="dialog"], .modal-backdrop [role="alertdialog"]');
        if (dialog) {
          const controls = [...dialog.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')];
          const first = controls[0];
          const last = controls.at(-1);
          if (!dialog.contains(document.activeElement)) {
            event.preventDefault();
            first?.focus();
          } else if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
          }
        }
      }
      if (!(event.metaKey || event.ctrlKey)) return;
      if (event.key.toLowerCase() === 'l' && screen === 'vault') {
        event.preventDefault();
        lockVault();
      }
      if (event.key.toLowerCase() === 'k' && screen === 'vault') {
        event.preventDefault();
        document.getElementById('vault-search')?.focus();
      }
    };
    window.addEventListener('keydown', onShortcut);
    return () => window.removeEventListener('keydown', onShortcut);
  });

  function emptyEntry(): Entry {
    return { id: '', service: '', username: '', password: '', notes: '', category: '' };
  }

  function showNotice(message: string, kind: NoticeKind = 'success') {
    notice = message;
    noticeKind = kind;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (notice = ''), kind === 'error' ? 6000 : 2600);
  }

  function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  async function showOperationError(error: unknown) {
    const message = errorMessage(error);
    showNotice(message, 'error');
    if (!message.includes('alterado por outro dispositivo')) return;
    try {
      const state = await Vault.State();
      conflict = state.conflict ?? null;
    } catch {
      conflict = null;
    }
  }

  async function openConflictVersion(path: string) {
    await Vault.LockVault();
    refreshGeneration++;
    entries = [];
    categories = [];
    revealed = {};
    closeEntryEditor();
    closeChangePassword();
    conflict = null;
    vaultPath = path;
    unlockPassword = '';
    screen = 'unlock';
  }

  async function chooseNewVault() {
    try {
      const path = await Vault.ChooseVaultToCreate();
      if (!path) return;
      vaultPath = path;
      newMasterPassword = '';
      confirmMasterPassword = '';
      screen = 'create';
    } catch (error) {
      await showOperationError(error);
    }
  }

  async function chooseExistingVault() {
    try {
      const path = await Vault.ChooseVaultToOpen();
      if (!path) return;
      vaultPath = path;
      unlockPassword = '';
      screen = 'unlock';
    } catch (error) {
      await showOperationError(error);
    }
  }

  async function createVault() {
    if (newMasterPassword !== confirmMasterPassword) {
      showNotice('As senhas mestras não coincidem.', 'error');
      return;
    }
    busy = true;
    try {
      await Vault.CreateVault(vaultPath, newMasterPassword);
      await enterVault();
      newMasterPassword = '';
      confirmMasterPassword = '';
      showNotice('Cofre criado e criptografado.');
    } catch (error) {
      await showOperationError(error);
    } finally {
      busy = false;
    }
  }

  async function unlockVault() {
    busy = true;
    try {
      await Vault.UnlockVault(vaultPath, unlockPassword);
      unlockPassword = '';
      await enterVault();
    } catch (error) {
      await showOperationError(error);
    } finally {
      busy = false;
    }
  }

  async function enterVault() {
    const state = await Vault.State();
    filename = state.filename;
    screen = 'vault';
    activeCategory = '';
    search = '';
    await refresh();
  }

  async function refresh() {
    const generation = ++refreshGeneration;
    try {
      const [nextEntries, nextCategories] = await Promise.all([
        Vault.ListEntries(search, activeCategory),
        Vault.Categories(),
      ]);
      if (generation !== refreshGeneration) return;
      entries = nextEntries ?? [];
      categories = nextCategories ?? [];
    } catch (error) {
      if (generation !== refreshGeneration) return;
      showNotice(errorMessage(error), 'error');
    }
  }

  async function lockVault() {
    refreshGeneration++;
    await Vault.LockVault();
    screen = 'welcome';
    entries = [];
    categories = [];
    revealed = {};
    vaultPath = '';
    filename = '';
    closeEntryEditor();
    closeChangePassword();
    newMasterPassword = '';
    confirmMasterPassword = '';
    unlockPassword = '';
    showNotice('Cofre bloqueado.');
  }

  function returnToWelcome() {
    screen = 'welcome';
    vaultPath = '';
    newMasterPassword = '';
    confirmMasterPassword = '';
    unlockPassword = '';
  }

  function closeEntryEditor() {
    editorOpen = false;
    form = emptyEntry();
    showEntryPassword = false;
    editing = false;
  }

  function closeChangePassword() {
    changePasswordOpen = false;
    currentMasterPassword = '';
    replacementMasterPassword = '';
    confirmReplacementPassword = '';
  }

  async function openNewEntry() {
    form = emptyEntry();
    editing = false;
    showEntryPassword = false;
    editorOpen = true;
  }

  async function openEditEntry(id: string) {
    try {
      form = await Vault.GetEntry(id);
      editing = true;
      showEntryPassword = false;
      editorOpen = true;
    } catch (error) {
      await showOperationError(error);
    }
  }

  async function saveEntry() {
    const wasEditing = editing;
    busy = true;
    try {
      await Vault.SaveEntry({ ...form });
      closeEntryEditor();
      await refresh();
      showNotice(wasEditing ? 'Registro atualizado.' : 'Senha salva no cofre.');
    } catch (error) {
      await showOperationError(error);
    } finally {
      busy = false;
    }
  }

  function removeEntry(entry: EntrySummary) {
    deleteConfirmation = { kind: 'entry', entry };
  }

  async function confirmDelete() {
    const pending = deleteConfirmation;
    if (!pending || busy) return;
    busy = true;
    try {
      if (pending.kind === 'entry') {
        await Vault.DeleteEntry(pending.entry.id);
        deleteConfirmation = null;
        await refresh();
        showNotice('Registro removido.');
      } else {
        categories = (await Vault.DeleteCategory(pending.name)) ?? [];
        if (activeCategory === pending.name) activeCategory = '';
        deleteConfirmation = null;
        await refresh();
        showNotice('Categoria removida.');
      }
    } catch (error) {
      await showOperationError(error);
    } finally {
      busy = false;
    }
  }

  async function revealPassword(entry: EntrySummary) {
    if (revealed[entry.id] !== undefined) {
      const next = { ...revealed };
      delete next[entry.id];
      revealed = next;
      return;
    }
    try {
      const password = await Vault.RevealPassword(entry.id);
      revealed = { ...revealed, [entry.id]: password };
    } catch (error) {
      await showOperationError(error);
    }
  }

  async function copyField(entry: EntrySummary, field: 'service' | 'username' | 'password') {
    try {
      const clearsClipboard = await Vault.CopyField(entry.id, field);
      showNotice(clearsClipboard ? 'Conteúdo copiado. Será limpo em 30 segundos se a área continuar sem alterações.' : 'Conteúdo copiado. Não foi possível garantir a limpeza automática nesta sessão.');
    } catch (error) {
      showNotice(errorMessage(error), 'error');
    }
  }

  async function generatePassword() {
    try {
      form.password = await Vault.GeneratePassword({ ...passwordOptions });
      showEntryPassword = true;
    } catch (error) {
      showNotice(errorMessage(error), 'error');
    }
  }

  async function addCategory() {
    try {
      categories = (await Vault.CreateCategory(newCategoryName)) ?? [];
      newCategoryName = '';
      categoryInputOpen = false;
      await refresh();
      showNotice('Categoria criada.');
    } catch (error) {
      await showOperationError(error);
    }
  }

  function removeCategory(name: string) {
    deleteConfirmation = { kind: 'category', name };
  }

  async function changeMasterPassword() {
    if (replacementMasterPassword !== confirmReplacementPassword) {
      showNotice('As novas senhas mestras não coincidem.', 'error');
      return;
    }
    busy = true;
    try {
      await Vault.ChangeMasterPassword(currentMasterPassword, replacementMasterPassword);
      closeChangePassword();
      showNotice('Senha mestra alterada.');
    } catch (error) {
      await showOperationError(error);
    } finally {
      busy = false;
    }
  }

  function passwordDots(length = 14) {
    return '•'.repeat(length);
  }
</script>

{#if screen === 'welcome'}
  <main class="welcome-shell">
    <div class="welcome-card">
      <div class="brand-lock"><span class="lock-shape"></span></div>
      <p class="eyebrow">SEU COFRE PESSOAL</p>
      <h1>Senhas seguras.<br /><span>Do seu jeito.</span></h1>
      <p class="welcome-copy">Guarde suas credenciais em um arquivo criptografado que fica sob seu controle.</p>
      <div class="welcome-actions">
        <button class="button button-primary button-large" onclick={chooseNewVault}>Criar um cofre <span aria-hidden="true">↗</span></button>
        <button class="button button-secondary button-large" onclick={chooseExistingVault}>Abrir um cofre existente</button>
      </div>
      <div class="welcome-foot"><span class="status-dot"></span>Criptografado no seu dispositivo <span class="foot-separator">·</span> Sem conta online</div>
    </div>
    <div class="welcome-decoration decoration-one"></div>
    <div class="welcome-decoration decoration-two"></div>
  </main>
{:else if screen === 'create'}
  <main class="auth-shell">
    <button class="back-link" onclick={returnToWelcome}>← Voltar</button>
    <section class="auth-card">
      <div class="small-lock"><span class="lock-shape"></span></div>
      <p class="eyebrow">NOVO COFRE</p>
      <h1>Crie sua senha mestra</h1>
      <p class="muted">Ela protege todas as suas senhas. Não poderá ser recuperada se você esquecê-la.</p>
      <div class="file-chip"><span class="file-icon">▧</span><span>{vaultPath.split('/').pop()}</span></div>
      <label class="field-label" for="master-password">Senha mestra</label>
      <input id="master-password" class="text-field" bind:value={newMasterPassword} type={showMasterPassword ? 'text' : 'password'} autocomplete="new-password" placeholder="Pelo menos 12 caracteres" onkeydown={(event) => event.key === 'Enter' && document.getElementById('confirm-master-password')?.focus()} />
      <label class="field-label" for="confirm-master-password">Confirme a senha mestra</label>
      <input id="confirm-master-password" class="text-field" bind:value={confirmMasterPassword} type={showMasterPassword ? 'text' : 'password'} autocomplete="new-password" placeholder="Digite novamente" onkeydown={(event) => event.key === 'Enter' && createVault()} />
      <label class="check-row show-password"><input type="checkbox" bind:checked={showMasterPassword} /> Mostrar senha</label>
      <button class="button button-primary button-large full-width" disabled={busy} onclick={createVault}>{busy ? 'Criando cofre…' : 'Criar cofre'}</button>
      <p class="fine-print">Sua senha mestra nunca é salva no arquivo.</p>
    </section>
  </main>
{:else if screen === 'unlock'}
  <main class="auth-shell">
    <button class="back-link" onclick={returnToWelcome}>← Voltar</button>
    <section class="auth-card">
      <div class="small-lock"><span class="lock-shape"></span></div>
      <p class="eyebrow">COFRE CRIPTOGRAFADO</p>
      <h1>Bem-vindo de volta</h1>
      <p class="muted">Informe a senha mestra para desbloquear seu cofre.</p>
      <div class="file-chip"><span class="file-icon">▧</span><span>{vaultPath.split('/').pop()}</span></div>
      <label class="field-label" for="unlock-password">Senha mestra</label>
      <input id="unlock-password" class="text-field" bind:value={unlockPassword} type="password" autocomplete="current-password" placeholder="Sua senha mestra" onkeydown={(event) => event.key === 'Enter' && unlockVault()} />
      <button class="button button-primary button-large full-width" disabled={busy || !unlockPassword} onclick={unlockVault}>{busy ? 'Desbloqueando…' : 'Desbloquear cofre'}</button>
      <p class="fine-print">O cofre será bloqueado novamente ao fechar o aplicativo.</p>
    </section>
  </main>
{:else}
  <main class="app-shell">
    <aside class="sidebar">
      <div class="sidebar-brand"><div class="brand-mark-small"><span class="lock-shape"></span></div><div><strong>meu cofre</strong><small>PESSOAL</small></div></div>
      <div class="vault-label"><span class="vault-icon">▧</span><span title={filename}>{filename}</span><span class="online-dot" title="Desbloqueado"></span></div>
      <button class:active={activeCategory === ''} class="nav-item" onclick={() => { activeCategory = ''; refresh(); }}><span class="nav-icon">▤</span><span>Todas as senhas</span><span class="nav-count">{entries.length}</span></button>
      <div class="section-heading"><span>CATEGORIAS</span><button class="icon-button small" aria-label="Adicionar categoria" title="Adicionar categoria" onclick={() => (categoryInputOpen = !categoryInputOpen)}>＋</button></div>
      {#if categoryInputOpen}
        <form class="category-create" onsubmit={(event) => { event.preventDefault(); addCategory(); }}>
          <input bind:value={newCategoryName} maxlength="32" placeholder="Nome da categoria" aria-label="Nome da categoria" />
          <button type="submit" aria-label="Salvar categoria">↵</button>
        </form>
      {/if}
      <nav class="category-list" aria-label="Categorias">
        {#each categories as category}
          <div class:active={activeCategory === category} class="category-row">
            <button class="category-button" onclick={() => { activeCategory = category; refresh(); }}><span class="category-dot"></span>{category}</button>
            <button class="category-remove" aria-label={`Excluir categoria ${category}`} title="Excluir categoria" onclick={() => removeCategory(category)}>×</button>
          </div>
        {/each}
      </nav>
      <div class="sidebar-spacer"></div>
      <div class="sidebar-security"><span class="shield">◇</span><div><strong>Protegido</strong><small>Argon2id + AES-256-GCM</small></div></div>
      <button class="nav-item settings-item" onclick={() => (changePasswordOpen = true)}><span class="nav-icon">⚙</span><span>Alterar senha mestra</span></button>
      <button class="nav-item lock-item" onclick={lockVault}><span class="nav-icon">⌑</span><span>Bloquear cofre</span><kbd>{shortcutModifier}L</kbd></button>
      <div class="sidebar-footer">ARQUIVO LOCAL · SUAS REGRAS</div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div class="breadcrumbs"><span>Meu cofre</span><span class="crumb-slash">/</span><strong>{activeCategory || 'Todas as senhas'}</strong></div>
        <div class="top-actions"><span class="encrypted-label"><span class="status-dot"></span>Criptografia ativa</span><button class="avatar" title="Cofre pessoal">FP</button></div>
      </header>
      <div class="page-content">
        <div class="page-heading">
          <div><p class="eyebrow">SEU ESPAÇO SEGURO</p><h1>{activeCategory || 'Todas as senhas'}<span class="heading-count">{entries.length}</span></h1><p class="page-subtitle">Suas credenciais, organizadas e protegidas.</p></div>
          <button class="button button-primary add-button" onclick={openNewEntry}><span class="plus">＋</span> Nova senha</button>
        </div>
        <div class="toolbar"><label class="search-box"><span class="search-icon">⌕</span><input id="vault-search" bind:value={search} oninput={refresh} placeholder="Buscar por serviço, usuário ou notas…" aria-label="Buscar senhas" /><kbd>{shortcutModifier}K</kbd></label><div class="sort-label"><span>ORDENADAS POR</span><strong>Serviço</strong></div></div>

        {#if entries.length === 0}
          <div class="empty-state"><div class="empty-icon">⌕</div><h2>{search ? 'Nenhum resultado encontrado' : activeCategory ? 'Categoria vazia' : 'Seu cofre está pronto'}</h2><p>{search ? 'Tente buscar por outro termo.' : activeCategory ? 'Adicione uma senha ou escolha outra categoria.' : 'Adicione sua primeira senha para começar.'}</p>{#if !search && !activeCategory}<button class="button button-primary" onclick={openNewEntry}>Adicionar primeira senha</button>{/if}</div>
        {:else}
          <div class="entry-list">
            {#each entries as entry (entry.id)}
              <article class="entry-card">
                <div class="service-icon">{entry.service.trim().charAt(0).toUpperCase()}</div>
                <div class="entry-main">
                  <div class="entry-title-row"><h2>{entry.service}</h2>{#if entry.category}<span class="category-tag">{entry.category}</span>{/if}</div>
                  <div class="entry-username">{entry.username || 'Sem usuário'}</div>
                  {#if entry.notes}<p class="entry-notes">{entry.notes}</p>{/if}
                  <div class="password-line"><span class="password-value">{revealed[entry.id] ?? passwordDots()}</span><button class="text-action" onclick={() => revealPassword(entry)}>{revealed[entry.id] !== undefined ? 'Ocultar' : 'Revelar'}</button></div>
                </div>
                <div class="entry-actions">
                  <button class="icon-button" aria-label="Copiar usuário" title="Copiar usuário" onclick={() => copyField(entry, 'username')}>▣<span>Usuário</span></button>
                  <button class="icon-button" aria-label="Copiar senha" title="Copiar senha" onclick={() => copyField(entry, 'password')}>⧉<span>Senha</span></button>
                  <button class="icon-button" aria-label="Copiar site ou serviço" title="Copiar site ou serviço" onclick={() => copyField(entry, 'service')}>↗<span>Site</span></button>
                  <span class="action-divider"></span>
                  <button class="icon-button compact" aria-label="Editar registro" title="Editar" onclick={() => openEditEntry(entry.id)}>✎</button>
                  <button class="icon-button compact danger-hover" aria-label="Remover registro" title="Remover" onclick={() => removeEntry(entry)}>⌫</button>
                </div>
              </article>
            {/each}
          </div>
        {/if}
        <footer class="content-footer"><span><span class="status-dot"></span> SALVAMENTO AUTOMÁTICO</span><span>Uma cópia criptografada é guardada antes de cada alteração.</span></footer>
      </div>
    </section>
  </main>
{/if}

{#if editorOpen}
  <div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && closeEntryEditor()}>
    <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="entry-modal-title" tabindex="-1">
      <div class="modal-heading"><div><p class="eyebrow">CREDENCIAL</p><h2 id="entry-modal-title">{editing ? 'Editar senha' : 'Nova senha'}</h2></div><button class="icon-button compact" aria-label="Fechar" onclick={closeEntryEditor}>×</button></div>
      <form onsubmit={(event) => { event.preventDefault(); saveEntry(); }}>
        <label class="field-label" for="entry-service">Site ou serviço <span class="required">*</span></label>
        <input id="entry-service" class="text-field" bind:value={form.service} required maxlength="160" placeholder="Ex.: e-mail, banco, loja" />
        <label class="field-label" for="entry-username">Usuário</label>
        <div class="input-with-action"><input id="entry-username" class="text-field" bind:value={form.username} maxlength="320" placeholder="Nome de usuário ou e-mail" /><span class="field-trailing">⌨</span></div>
        <label class="field-label" for="entry-password">Senha <span class="required">*</span></label>
        <div class="password-editor"><input id="entry-password" class="text-field" bind:value={form.password} required maxlength="4096" type={showEntryPassword ? 'text' : 'password'} autocomplete="off" placeholder="Digite ou gere uma senha" /><button type="button" class="text-action" onclick={() => (showEntryPassword = !showEntryPassword)}>{showEntryPassword ? 'Ocultar' : 'Revelar'}</button></div>
        <div class="generator-panel"><div class="generator-title"><span>GERADOR DE SENHAS</span><label class="length-label">Tamanho <input type="number" min="8" max="128" bind:value={passwordOptions.length} /></label></div><div class="generator-options"><label><input type="checkbox" bind:checked={passwordOptions.uppercase} /> Maiúsculas</label><label><input type="checkbox" bind:checked={passwordOptions.lowercase} /> Minúsculas</label><label><input type="checkbox" bind:checked={passwordOptions.numbers} /> Números</label><label><input type="checkbox" bind:checked={passwordOptions.symbols} /> Símbolos</label></div><button type="button" class="generate-button" onclick={generatePassword}>⟳ Gerar senha segura</button></div>
        <label class="field-label" for="entry-category">Categoria</label>
        <select id="entry-category" class="text-field select-field" bind:value={form.category}><option value="">Sem categoria</option>{#each categories as category}<option value={category}>{category}</option>{/each}</select>
        <label class="field-label" for="entry-notes">Notas</label>
        <textarea id="entry-notes" class="text-field notes-field" bind:value={form.notes} rows="3" maxlength="4000" placeholder="Informações úteis sobre esta conta"></textarea>
        <div class="modal-actions"><button type="button" class="button button-secondary" onclick={closeEntryEditor}>Cancelar</button><button type="submit" class="button button-primary" disabled={busy}>{busy ? 'Salvando…' : editing ? 'Salvar alterações' : 'Salvar senha'}</button></div>
      </form>
    </div>
  </div>
{/if}

{#if changePasswordOpen}
  <div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && closeChangePassword()}>
    <div class="modal-card narrow-modal" role="dialog" aria-modal="true" aria-labelledby="master-modal-title" tabindex="-1">
      <div class="modal-heading"><div><p class="eyebrow">SEGURANÇA</p><h2 id="master-modal-title">Alterar senha mestra</h2></div><button class="icon-button compact" aria-label="Fechar" onclick={closeChangePassword}>×</button></div>
      <form onsubmit={(event) => { event.preventDefault(); changeMasterPassword(); }}>
        <label class="field-label" for="current-master">Senha mestra atual</label><input id="current-master" class="text-field" type="password" bind:value={currentMasterPassword} autocomplete="current-password" required />
        <label class="field-label" for="replacement-master">Nova senha mestra</label><input id="replacement-master" class="text-field" type="password" bind:value={replacementMasterPassword} autocomplete="new-password" minlength="12" required />
        <label class="field-label" for="confirm-replacement-master">Confirme a nova senha</label><input id="confirm-replacement-master" class="text-field" type="password" bind:value={confirmReplacementPassword} autocomplete="new-password" minlength="12" required />
        <p class="fine-print left">O cofre será recriptografado. A cópia anterior ficará protegida no arquivo de segurança.</p>
        <div class="modal-actions"><button type="button" class="button button-secondary" onclick={closeChangePassword}>Cancelar</button><button type="submit" class="button button-primary" disabled={busy}>{busy ? 'Alterando…' : 'Alterar senha'}</button></div>
      </form>
    </div>
  </div>
{/if}

{#if conflict}
  <div class="modal-backdrop" role="presentation">
    <div class="modal-card narrow-modal" role="alertdialog" aria-modal="true" aria-labelledby="conflict-title" tabindex="-1">
      <div class="modal-heading"><div><p class="eyebrow">CONFLITO DE SINCRONIZAÇÃO</p><h2 id="conflict-title">Duas versões foram preservadas</h2></div></div>
      <p>O arquivo sincronizado mudou durante a gravação. A alteração que encontrou conflito está na sua versão local. Escolha qual arquivo abrir; para continuar com essa alteração, abra sua cópia. Será necessário informar a senha mestra correspondente.</p>
      <div class="conflict-path"><strong>Versão sincronizada</strong><code>{conflict.originalPath}</code></div>
      <div class="conflict-path"><strong>Sua versão local</strong><code>{conflict.localPath}</code></div>
      <div class="modal-actions conflict-actions">
        <button class="button button-secondary" onclick={() => (conflict = null)}>Fechar aviso</button>
        <button class="button button-secondary" onclick={() => openConflictVersion(conflict!.originalPath)}>Abrir sincronizada</button>
        <button class="button button-primary" onclick={() => openConflictVersion(conflict!.localPath)}>Abrir minha cópia</button>
      </div>
    </div>
  </div>
{/if}

{#if deleteConfirmation}
  <div class="modal-backdrop" role="presentation" onclick={(event) => event.target === event.currentTarget && !busy && (deleteConfirmation = null)}>
    <div class="modal-card narrow-modal" role="alertdialog" aria-modal="true" aria-labelledby="delete-title" aria-describedby="delete-description" tabindex="-1">
      <div class="modal-heading"><div><p class="eyebrow">CONFIRMAR EXCLUSÃO</p><h2 id="delete-title">{deleteConfirmation.kind === 'entry' ? 'Excluir senha?' : 'Excluir categoria?'}</h2></div></div>
      <p id="delete-description">{deleteConfirmation.kind === 'entry'
        ? `A senha de “${deleteConfirmation.entry.service}” será removida permanentemente do cofre.`
        : `A categoria “${deleteConfirmation.name}” será excluída. Os registros serão mantidos sem categoria.`}</p>
      <div class="modal-actions">
        <button type="button" class="button button-secondary" disabled={busy} onclick={() => (deleteConfirmation = null)}>Cancelar</button>
        <button type="button" class="button button-danger" disabled={busy} onclick={confirmDelete}>{busy ? 'Excluindo…' : deleteConfirmation.kind === 'entry' ? 'Excluir senha' : 'Excluir categoria'}</button>
      </div>
    </div>
  </div>
{/if}

{#if notice}
  <div class:notice-error={noticeKind === 'error'} class="toast-message" role="status">{notice}</div>
{/if}
