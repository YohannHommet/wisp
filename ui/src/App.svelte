<script lang="ts">
  import { onMount } from 'svelte';

  // Import Tauri APIs conditionally to prevent crashes in standalone web previews
  let invoke = async (cmd: string, args: any = {}): Promise<any> => {
    console.log("[Mock Invoke]", cmd, args);
    if (cmd === 'generate_pairing_code') return '7-tiger-saturn';
    if (cmd === 'open_file_dialog') return '/mock/path/to/project_video.mp4';
    if (cmd === 'open_dir_dialog') return '/mock/downloads';
    return null;
  };

  let listen = async (event: string, callback: (event: any) => void): Promise<any> => {
    console.log("[Mock Listen]", event);
    return () => {};
  };

  onMount(async () => {
    if (window.__TAURI_INTERNALS__) {
      const core = await import('@tauri-apps/api/core');
      const event = await import('@tauri-apps/api/event');
      invoke = core.invoke;
      listen = event.listen;
    }
  });

  // State Management
  let activeTab = 'dashboard'; // 'dashboard' | 'settings'
  let transferState = 'idle'; // 'idle' | 'waiting' | 'transferring' | 'done' | 'error'
  
  let currentFile = '';
  let downloadDir = '';
  let pairingCode = '';
  let enteredCode = '';
  let relayUrl = 'https://relay.wisp.net'; // Default relay server
  let errorMessage = '';
  let sidebarExpanded = true;

  // Progress metrics
  let bytesTransferred = 0n;
  let totalBytes = 0n;
  let transferSpeed = '0 MB/s';
  let eta = 'Calculating...';
  
  let lastBytes = 0n;
  let lastTime = Date.now();
  let startTime = Date.now();

  let unlistenProgress: any = null;
  let unlistenError: any = null;

  // Generate a random session ID
  const sessionId = Math.random().toString(36).substring(7);

  function resetTransfer() {
    transferState = 'idle';
    currentFile = '';
    pairingCode = '';
    enteredCode = '';
    errorMessage = '';
    bytesTransferred = 0n;
    totalBytes = 0n;
    transferSpeed = '0 MB/s';
    eta = 'Calculating...';
    if (unlistenProgress) unlistenProgress();
    if (unlistenError) unlistenError();
  }

  async function handleSend() {
    try {
      const path = await invoke('open_file_dialog');
      currentFile = path;
      pairingCode = await invoke('generate_pairing_code');
      transferState = 'waiting';

      // Setup listeners before starting session
      unlistenProgress = await listen('transfer-progress', (event: any) => {
        const payload = event.payload;
        if (transferState !== 'transferring') {
          transferState = 'transferring';
          startTime = Date.now();
          lastTime = Date.now();
        }
        
        bytesTransferred = BigInt(payload.transferred);
        totalBytes = BigInt(payload.total);
        calculateSpeedAndEta();
      });

      unlistenError = await listen('transfer-error', (event: any) => {
        errorMessage = event.payload;
        transferState = 'error';
      });

      // Start the transfer thread in background
      invoke('start_send_session', {
        sessionId,
        filepath: currentFile,
        relay: relayUrl ? relayUrl : null
      }).then(() => {
        if (transferState === 'transferring') {
          transferState = 'done';
        }
      }).catch((err) => {
        errorMessage = err;
        transferState = 'error';
      });

    } catch (err: any) {
      if (err !== 'File selection cancelled') {
        errorMessage = err.toString();
        transferState = 'error';
      }
    }
  }

  async function handleReceive() {
    if (!enteredCode) return;
    try {
      const dir = await invoke('open_dir_dialog');
      downloadDir = dir;
      transferState = 'transferring';
      startTime = Date.now();
      lastTime = Date.now();

      // Setup listeners before starting session
      unlistenProgress = await listen('transfer-progress', (event: any) => {
        const payload = event.payload;
        bytesTransferred = BigInt(payload.transferred);
        totalBytes = BigInt(payload.total);
        calculateSpeedAndEta();
      });

      unlistenError = await listen('transfer-error', (event: any) => {
        errorMessage = event.payload;
        transferState = 'error';
      });

      // Start the transfer thread in background
      invoke('start_recv_session', {
        sessionId,
        code: enteredCode,
        downloadDir,
        relay: relayUrl ? relayUrl : null
      }).then(() => {
        transferState = 'done';
      }).catch((err) => {
        errorMessage = err;
        transferState = 'error';
      });

    } catch (err: any) {
      if (err !== 'Directory selection cancelled') {
        errorMessage = err.toString();
        transferState = 'error';
      }
    }
  }

  async function handleCancel() {
    await invoke('cancel_transfer', { sessionId });
    resetTransfer();
  }

  function calculateSpeedAndEta() {
    const now = Date.now();
    const timeDelta = (now - lastTime) / 1000;
    
    if (timeDelta >= 0.5) {
      const bytesDelta = bytesTransferred - lastBytes;
      const speedBps = Number(bytesDelta) / timeDelta;
      
      // MB/s formatting
      transferSpeed = (speedBps / (1024 * 1024)).toFixed(1) + ' MB/s';
      
      // ETA formatting
      if (speedBps > 0) {
        const remainingBytes = Number(totalBytes - bytesTransferred);
        const etaSeconds = Math.round(remainingBytes / speedBps);
        eta = etaSeconds + 's remaining';
      } else {
        eta = 'Calculating...';
      }
      
      lastBytes = bytesTransferred;
      lastTime = now;
    }
  }

  // Helper: formatted progress percentage
  $: progressPercent = totalBytes > 0n ? Math.round(Number(bytesTransferred * 100n / totalBytes)) : 0;
</script>

<div class="glass-container">
  <!-- Sidebar Navigation -->
  <aside class="sidebar" class:collapsed={!sidebarExpanded}>
    <div class="brand">
      <!-- Nano Banana Logo -->
      <svg class="brand-logo" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent-terracotta)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 21c4-1 12-4 15-16.5" />
        <path d="M5 21c7.5-6.5 12-11.5 15-16.5" />
        <circle cx="20" cy="4.5" r="1.5" fill="var(--accent-terracotta)" stroke="none" />
        <circle cx="5" cy="21" r="1.5" fill="var(--accent-terracotta)" stroke="none" />
      </svg>
      {#if sidebarExpanded}
        <span class="brand-name">wisp</span>
      {/if}
    </div>

    <nav class="nav-links">
      <button class="nav-btn" class:active={activeTab === 'dashboard'} on:click={() => activeTab = 'dashboard'}>
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="7" height="9" rx="1" />
          <rect x="14" y="3" width="7" height="5" rx="1" />
          <rect x="14" y="12" width="7" height="9" rx="1" />
          <rect x="3" y="16" width="7" height="5" rx="1" />
        </svg>
        {#if sidebarExpanded}
          <span class="nav-text">Dashboard</span>
        {/if}
      </button>

      <button class="nav-btn" class:active={activeTab === 'settings'} on:click={() => activeTab = 'settings'}>
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
          <line x1="4" y1="21" x2="4" y2="14" />
          <line x1="4" y1="10" x2="4" y2="3" />
          <line x1="12" y1="21" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12" y2="3" />
          <line x1="20" y1="21" x2="20" y2="16" />
          <line x1="20" y1="12" x2="20" y2="3" />
          <line x1="1" y1="14" x2="7" y2="14" />
          <line x1="9" y1="8" x2="15" y2="8" />
          <line x1="17" y1="16" x2="23" y2="16" />
        </svg>
        {#if sidebarExpanded}
          <span class="nav-text">Settings</span>
        {/if}
      </button>

      <!-- Collapse Toggle -->
      <button class="nav-btn" style="margin-top: auto;" on:click={() => sidebarExpanded = !sidebarExpanded}>
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
          {#if sidebarExpanded}
            <polyline points="15 18 9 12 15 6" />
          {:else}
            <polyline points="9 18 15 12 9 6" />
          {/if}
        </svg>
        {#if sidebarExpanded}
          <span class="nav-text">Collapse</span>
        {/if}
      </button>
    </nav>

    {#if sidebarExpanded}
      <div class="sidebar-footer">
        Build 108
      </div>
    {/if}
  </aside>

  <!-- Main View Area -->
  <main class="main-content">
    {#if activeTab === 'dashboard'}
      <div class="view-header">
        <h2>Send & Receive</h2>
        <p>Transfer secure files peer-to-peer without servers</p>
      </div>

      {#if transferState === 'idle'}
        <!-- Drag & Drop Zone / Send Picker -->
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div class="drop-zone" on:click={handleSend}>
          <svg class="drop-icon" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="12" y1="18" x2="12" y2="12" />
            <polyline points="9 15 12 12 15 15" />
          </svg>
          <span class="drop-text">Drag and drop file here or browse</span>
          <span class="drop-subtext">File is kept fully private during transfer</span>
        </div>

        <!-- Code Entry for Receiver -->
        <div class="code-entry-box">
          <span class="drop-subtext" style="text-transform: uppercase; font-weight: 600;">Receive File from Peer</span>
          <div class="code-row">
            <input 
              id="pairing-code-input"
              type="text" 
              class="input-glow" 
              placeholder="Enter pairing code..." 
              bind:value={enteredCode} 
            />
            <button class="btn-primary" on:click={handleReceive}>Receive</button>
          </div>
        </div>

      {:else if transferState === 'waiting'}
        <!-- Waiting on peer to connect screen -->
        <div class="code-present-container">
          <span class="present-label">Your Pairing Code</span>
          <!-- svelte-ignore a11y-click-events-have-key-events -->
          <!-- svelte-ignore a11y-no-static-element-interactions -->
          <div class="pairing-code" on:click={() => navigator.clipboard.writeText(pairingCode)}>
            {pairingCode}
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
            </svg>
          </div>
          <span class="drop-subtext">Click to copy code. Send it to the receiver.</span>
          <span class="waiting-sub">Awaiting peer connection...</span>
          <button class="btn-danger" style="margin-top: 16px;" on:click={handleCancel}>Cancel</button>
        </div>

      {:else if transferState === 'transferring'}
        <!-- Active transfer screen -->
        <div class="transfer-progress-view">
          <div class="transfer-meta">
            <span class="filename-txt">{currentFile ? currentFile.split('/').pop() : 'Receiving File...'}</span>
            <span style="font-weight: 700; color: var(--text-primary);">{progressPercent}%</span>
          </div>

          <div class="linear-progress-wrapper">
            <div class="linear-progress-bg">
              <div class="linear-progress-bar" style="width: {progressPercent}%;"></div>
            </div>
          </div>

          <div class="transfer-meta" style="margin-top: -8px;">
            <div class="transfer-stats">
              <span>{transferSpeed}</span>
              <span style="color: var(--text-muted);">·</span>
              <span>{eta}</span>
            </div>
          </div>

          <button class="btn-danger" on:click={handleCancel}>Cancel Transfer</button>
        </div>

      {:else if transferState === 'done'}
        <!-- Success Screen -->
        <div class="code-present-container">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-sage)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          <h3 style="font-size: 20px; font-weight: 700; margin: 8px 0 2px 0;">Transfer Completed</h3>
          <p class="drop-subtext">File integrity verified via BLAKE3 checksum.</p>
          <button class="btn-primary" style="margin-top: 16px;" on:click={resetTransfer}>Back to Dashboard</button>
        </div>

      {:else if transferState === 'error'}
        <!-- Error Screen -->
        <div class="code-present-container">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent-coral)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <h3 style="font-size: 20px; font-weight: 700; margin: 8px 0 2px 0;">Transfer Failed</h3>
          <p class="drop-subtext" style="color: var(--accent-coral);">{errorMessage}</p>
          <button class="btn-primary" style="margin-top: 16px;" on:click={resetTransfer}>Dismiss</button>
        </div>
      {/if}

    {:else if activeTab === 'settings'}
      <div class="view-header">
        <h2>Settings</h2>
        <p>Configure network interfaces and relay nodes</p>
      </div>

      <div style="display: flex; flex-direction: column; gap: 24px; max-width: 480px;">
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <span class="drop-subtext" style="text-transform: uppercase;">Relay Server URL</span>
          <input 
            id="relay-url-input"
            type="text" 
            class="input-glow" 
            placeholder="e.g. https://relay.wisp.net" 
            bind:value={relayUrl} 
          />
          <span class="drop-subtext">If empty, LAN-only mode (mDNS) will be enforced.</span>
        </div>

        <div style="display: flex; flex-direction: column; gap: 8px;">
          <span class="drop-subtext" style="text-transform: uppercase;">Connection Security</span>
          <div style="display: flex; align-items: center; gap: 12px; background: rgba(255,255,255,0.01); padding: 14px; border-radius: 16px; border: 1px solid var(--panel-border);">
            <div style="width: 8px; height: 8px; border-radius: 50%; background: var(--accent-sage);"></div>
            <span style="font-size: 13px; font-weight: 600; color: var(--text-primary);">SPAKE2 Pinned Handshake + TLS 1.3 ALPN</span>
          </div>
        </div>
      </div>
    {/if}
  </main>
</div>
