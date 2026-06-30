<script lang="ts">
  import { onMount } from 'svelte';

  // Import Tauri APIs conditionally to prevent crashes in web preview
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
  $: progressOffset = 502 - (502 * progressPercent) / 100;
</script>

<svg style="position: absolute; width: 0; height: 0;">
  <defs>
    <linearGradient id="brand-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f2fe" />
      <stop offset="100%" stop-color="#9b51e0" />
    </linearGradient>
    <linearGradient id="ring-grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f2fe" />
      <stop offset="100%" stop-color="#9b51e0" />
    </linearGradient>
  </defs>
</svg>

<div class="glass-container">
  <!-- Sidebar Navigation -->
  <aside class="sidebar">
    <div class="brand">
      <svg class="brand-icon" viewBox="0 0 32 32">
        <path d="M16 2 L2 9 L2 23 L16 30 L30 23 L30 9 Z" />
        <path d="M16 8 L6 13 L16 18 L26 13 Z" />
        <path d="M16 18 L16 30" />
      </svg>
      <span class="brand-name">WISP</span>
    </div>

    <nav class="nav-links">
      <button class="nav-btn" class:active={activeTab === 'dashboard'} on:click={() => activeTab = 'dashboard'}>
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <rect width="7" height="9" x="3" y="3" rx="1" />
          <rect width="7" height="5" x="14" y="3" rx="1" />
          <rect width="7" height="9" x="14" y="12" rx="1" />
          <rect width="7" height="5" x="3" y="16" rx="1" />
        </svg>
        Dashboard
      </button>

      <button class="nav-btn" class:active={activeTab === 'settings'} on:click={() => activeTab = 'settings'}>
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
        Settings
      </button>
    </nav>

    <div class="sidebar-footer">
      Wisp Desktop v0.1.0
    </div>
  </aside>

  <!-- Main View Area -->
  <main class="main-content">
    {#if activeTab === 'dashboard'}
      <div class="view-header">
        <h2>Transfer Files</h2>
        <p>Ultra-fast peer-to-peer file sharing over LAN or WAN</p>
      </div>

      {#if transferState === 'idle'}
        <!-- Drag & Drop Zone / Send Picker -->
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <div class="drop-zone" on:click={handleSend}>
          <svg class="drop-icon" fill="none" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 16.5V9.75m0 0l3 3m-3-3l-3 3M6.75 19.5a4.5 4.5 0 01-1.41-8.775 5.25 5.25 0 0110.233-2.33 3 3 0 013.758 3.848A3.752 3.752 0 0118 19.5H6.75z" />
          </svg>
          <span class="drop-text">Drag and drop files here or browse</span>
          <span class="drop-subtext">Supports single/multiple files or directories</span>
        </div>

        <!-- Code Entry for Receiver -->
        <div class="code-entry-box">
          <label for="pairing-code-input" class="drop-subtext" style="text-transform: uppercase; letter-spacing: 1px;">Receive File from Peer</label>
          <div class="code-row">
            <input 
              id="pairing-code-input"
              type="text" 
              class="input-glow" 
              placeholder="Enter pairing code (e.g. 7-tiger-saturn)" 
              bind:value={enteredCode} 
            />
            <button class="btn-primary" on:click={handleReceive}>Receive</button>
          </div>
        </div>

      {:else if transferState === 'waiting'}
        <!-- Waiting on peer to connect screen -->
        <div class="code-present-container">
          <span class="present-label">Your Pairing Code</span>
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <div class="pairing-code" on:click={() => navigator.clipboard.writeText(pairingCode)}>
            {pairingCode}
          </div>
          <span class="drop-subtext">Click to copy. Send this code to the receiver.</span>
          <span class="waiting-sub">Awaiting peer connection...</span>
          <button class="btn-danger" style="margin-top: 24px;" on:click={handleCancel}>Cancel</button>
        </div>

      {:else if transferState === 'transferring'}
        <!-- Active transfer screen -->
        <div class="transfer-progress-view">
          <div class="progress-ring-container">
            <svg width="180" height="180">
              <circle class="progress-ring-bg" cx="90" cy="90" r="80" />
              <circle class="progress-ring-fg" cx="90" cy="90" r="80" 
                      style="stroke-dasharray: 502; stroke-dashoffset: {progressOffset};" />
            </svg>
            <div class="progress-text-center">{progressPercent}%</div>
          </div>

          <div class="transfer-meta">
            <span class="filename-txt">{currentFile ? currentFile.split('/').pop() : 'Receiving File...'}</span>
            <div class="transfer-stats">
              <span>{transferSpeed}</span>
              <div class="stats-divider"></div>
              <span>{eta}</span>
            </div>
          </div>

          <button class="btn-danger" on:click={handleCancel}>Cancel Transfer</button>
        </div>

      {:else if transferState === 'done'}
        <!-- Success Screen -->
        <div class="code-present-container">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2">
            <circle cx="12" cy="12" r="10" />
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4" />
          </svg>
          <h3 style="font-size: 24px; font-weight: 800; margin: 12px 0 4px 0;">Transfer Completed</h3>
          <p class="drop-subtext">File integrity verified via BLAKE3 checksum.</p>
          <button class="btn-primary" style="margin-top: 16px;" on:click={resetTransfer}>Back to Dashboard</button>
        </div>

      {:else if transferState === 'error'}
        <!-- Error Screen -->
        <div class="code-present-container">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" stroke-width="2">
            <circle cx="12" cy="12" r="10" />
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <h3 style="font-size: 24px; font-weight: 800; margin: 12px 0 4px 0;">Transfer Failed</h3>
          <p class="drop-subtext" style="color: var(--accent-red);">{errorMessage}</p>
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
          <label class="drop-subtext" style="text-transform: uppercase;" for="relay-url-input">Relay Server URL</label>
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
          <label class="drop-subtext" style="text-transform: uppercase;">Connection Security</label>
          <div style="display: flex; align-items: center; gap: 12px; background: rgba(255,255,255,0.02); padding: 12px; border-radius: 12px; border: 1px solid var(--panel-border);">
            <div style="width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green);"></div>
            <span style="font-size: 14px; font-weight: 600;">SPAKE2 Pinned Handshake + TLS 1.3 ALPN</span>
          </div>
        </div>
      </div>
    {/if}
  </main>
</div>
