<script lang="ts">
  import { onMount, onDestroy } from 'svelte';

  // Import Tauri APIs conditionally to prevent crashes in standalone web previews
  let invoke = async (cmd: string, args: any = {}): Promise<any> => {
    console.log("[Mock Invoke]", cmd, args);
    if (cmd === 'generate_pairing_code') return '7-tiger-saturn';
    if (cmd === 'open_file_dialog') return '/mock/path/to/project_video.mp4';
    if (cmd === 'open_dir_dialog') return '/mock/downloads';
    if (cmd === 'get_device_info') return { friendly_name: 'Wisp Client (Preview)', fingerprint: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' };
    if (cmd === 'get_trusted_peers') return [
      { friendly_name: 'Trusted Peer (Mock)', certificate_fingerprint: 'mock-fingerprint', last_seen_ip: '192.168.1.100' }
    ];
    return null;
  };

  let listen = async (event: string, callback: (event: any) => void): Promise<any> => {
    console.log("[Mock Listen]", event);
    return () => {};
  };

  // Persistent LAN Device Discovery States
  let myDeviceInfo = { friendly_name: 'Wisp Client (Preview)', fingerprint: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' };
  let discoveredPeers: any[] = [];
  let trustedPeers: any[] = [];
  
  let showPairingModal = false;
  let pairingTargetPeer: any = null;
  let pairingMode: 'idle' | 'hosting' | 'connecting' | 'success' | 'error' = 'idle';
  let pairingCodeInput = '';
  let incomingPairedFile: any = null;
  let unlistenPeers: any = null;
  let unlistenIncomingFile: any = null;

  async function loadPeersAndInfo() {
    try {
      const info = await invoke('get_device_info');
      if (info) myDeviceInfo = info;
      
      const list = await invoke('get_trusted_peers');
      if (list) trustedPeers = list;
    } catch (e) {
      console.warn("Failed to load device info or trusted peers list:", e);
    }
  }

  onMount(async () => {
    if (window.__TAURI_INTERNALS__) {
      const core = await import('@tauri-apps/api/core');
      const event = await import('@tauri-apps/api/event');
      invoke = core.invoke;
      listen = event.listen;

      await loadPeersAndInfo();

      // Listen to peer updates from background discovery thread
      unlistenPeers = await listen('peers-updated', (event: any) => {
        discoveredPeers = event.payload || [];
      });

      // Listen to incoming file requests from trusted peers
      unlistenIncomingFile = await listen('incoming-paired-file', (event: any) => {
        incomingPairedFile = event.payload;
      });
    }
  });

  // State Management
  let activeTab = 'dashboard'; // 'dashboard' | 'settings'
  let transferState = 'idle'; // 'idle' | 'waiting' | 'transferring' | 'done' | 'error'
  let sidebarCollapsed = false;
  let currentFile = '';
  let downloadDir = '';
  let pairingCode = '';
  let enteredCode = '';
  let relayUrl = 'https://relay.wisp.net'; // Default relay server
  let errorMessage = '';

  // Progress metrics
  let bytesTransferred = BigInt(0);
  let totalBytes = BigInt(0);
  let transferSpeed = '0 MB/s';
  let eta = 'Calculating...';
  
  let lastBytes = BigInt(0);
  let lastTime = Date.now();
  let startTime = Date.now();

  let unlistenProgress: any = null;
  let unlistenError: any = null;

  // Active session ID
  let activeSessionId = '';

  function resetTransfer() {
    transferState = 'idle';
    currentFile = '';
    pairingCode = '';
    enteredCode = '';
    errorMessage = '';
    bytesTransferred = BigInt(0);
    totalBytes = BigInt(0);
    lastBytes = BigInt(0);
    transferSpeed = '0 MB/s';
    eta = 'Calculating...';
    if (unlistenProgress) {
      unlistenProgress();
      unlistenProgress = null;
    }
    if (unlistenError) {
      unlistenError();
      unlistenError = null;
    }
  }

  onDestroy(() => {
    if (unlistenProgress) unlistenProgress();
    if (unlistenError) unlistenError();
    if (unlistenPeers) unlistenPeers();
    if (unlistenIncomingFile) unlistenIncomingFile();
  });

  let copied = false;
  async function copyCodeToClipboard() {
    try {
      await navigator.clipboard.writeText(pairingCode);
      copied = true;
      setTimeout(() => {
        copied = false;
      }, 1500);
    } catch (e) {
      console.error("Failed to copy pairing code", e);
    }
  }

  // Start hosting a pairing session (role A)
  async function hostPairing() {
    try {
      pairingMode = 'hosting';
      // Generate code
      pairingCodeInput = await invoke('generate_pairing_code');
      activeSessionId = Math.random().toString(36).substring(7);
      
      // Call start_pairing_host
      const result = await invoke('start_pairing_host', {
        sessionId: activeSessionId,
        code: pairingCodeInput
      });

      if (result) {
        pairingMode = 'success';
        await loadPeersAndInfo();
        setTimeout(() => {
          showPairingModal = false;
          pairingMode = 'idle';
        }, 1500);
      }
    } catch (err: any) {
      errorMessage = err?.toString() || 'Pairing timed out or failed';
      pairingMode = 'error';
    }
  }

  // Connect to a hosting pairing peer (role B)
  async function connectPairing() {
    if (!pairingCodeInput || !pairingTargetPeer) return;
    try {
      pairingMode = 'connecting';
      const result = await invoke('pair_with_peer', {
        code: pairingCodeInput,
        address: pairingTargetPeer.address,
        fingerprint: pairingTargetPeer.fingerprint
      });

      if (result) {
        pairingMode = 'success';
        await loadPeersAndInfo();
        setTimeout(() => {
          showPairingModal = false;
          pairingMode = 'idle';
        }, 1500);
      }
    } catch (err: any) {
      errorMessage = err?.toString() || 'Pairing connection failed';
      pairingMode = 'error';
    }
  }

  // Delete a paired peer
  async function deletePeer(fingerprint: string) {
    try {
      await invoke('delete_trusted_peer', { fingerprint });
      await loadPeersAndInfo();
    } catch (e) {
      console.error(e);
    }
  }

  // Direct Send to Paired Peer (Role A)
  async function directSendToPeer(peer: any) {
    try {
      const filepath = await invoke('open_file_dialog');
      if (!filepath) return;

      resetTransfer();
      activeSessionId = Math.random().toString(36).substring(7);
      currentFile = filepath;
      
      // The pairing code is set to the peer's certificate fingerprint!
      pairingCode = peer.certificate_fingerprint;
      transferState = 'waiting';

      // Setup progress/error listeners
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

      // Start standard send session using peer fingerprint as code word
      invoke('start_send_session', {
        sessionId: activeSessionId,
        filepath: currentFile,
        relay: null // local LAN direct transfer!
      }).then(() => {
        if (transferState === 'transferring') {
          transferState = 'done';
        }
      }).catch((err) => {
        errorMessage = err;
        transferState = 'error';
      });

    } catch (err: any) {
      errorMessage = err?.toString() || 'Direct send failed';
      transferState = 'error';
    }
  }

  // Accept incoming transfer request from paired peer (Role B)
  async function acceptIncomingPairedFile() {
    if (!incomingPairedFile) return;
    try {
      const codeToUse = myDeviceInfo.fingerprint; // our own fingerprint is the pairing code!
      incomingPairedFile = null; // dismiss popup

      const dir = await invoke('open_dir_dialog');
      if (!dir) return;

      resetTransfer();
      downloadDir = dir;
      transferState = 'transferring';
      startTime = Date.now();
      lastTime = Date.now();
      activeSessionId = Math.random().toString(36).substring(7);

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

      invoke('start_recv_session', {
        sessionId: activeSessionId,
        code: codeToUse,
        downloadDir,
        relay: null // LAN direct!
      }).then(() => {
        if (transferState === 'transferring') {
          transferState = 'done';
        }
      }).catch((err) => {
        errorMessage = err;
        transferState = 'error';
      });

    } catch (err: any) {
      errorMessage = err?.toString() || 'Direct receive failed';
      transferState = 'error';
    }
  }

  let isDragging = false;

  async function startSendSession(filepath: string) {
    try {
      resetTransfer();
      activeSessionId = Math.random().toString(36).substring(7);
      currentFile = filepath;
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
        sessionId: activeSessionId,
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
      const errStr = err?.toString() || '';
      if (!errStr.includes('cancelled') && !errStr.includes('Cancel')) {
        errorMessage = errStr;
        transferState = 'error';
      }
    }
  }

  async function handleSend() {
    try {
      const path = await invoke('open_file_dialog');
      if (path) {
        await startSendSession(path);
      }
    } catch (err: any) {
      const errStr = err?.toString() || '';
      if (!errStr.includes('cancelled') && !errStr.includes('Cancel')) {
        errorMessage = errStr;
        transferState = 'error';
      }
    }
  }

  function handleDragOver(e: DragEvent) {
    e.preventDefault();
    isDragging = true;
  }

  function handleDragLeave() {
    isDragging = false;
  }

  async function handleDrop(e: DragEvent) {
    e.preventDefault();
    isDragging = false;
    
    if (e.dataTransfer && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      // Inside Tauri, File objects from HTML5 drag-and-drop contain a custom .path property:
      const path = (file as any).path;
      if (path) {
        await startSendSession(path);
      } else {
        // Fallback for standard browsers in preview
        await startSendSession('/mock/dragged/' + file.name);
      }
    }
  }

  async function handleReceive() {
    if (!enteredCode) return;
    try {
      const codeToUse = enteredCode;
      resetTransfer();
      enteredCode = codeToUse;

      const dir = await invoke('open_dir_dialog');
      downloadDir = dir;
      transferState = 'transferring';
      startTime = Date.now();
      lastTime = Date.now();
      activeSessionId = Math.random().toString(36).substring(7);

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
        sessionId: activeSessionId,
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
    if (activeSessionId) {
      await invoke('cancel_transfer', { sessionId: activeSessionId });
    }
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

  function getProgressPercent(transferred: bigint, total: bigint): number {
    if (total > BigInt(0)) {
      return Math.round(Number(transferred * BigInt(100) / total));
    }
    return 0;
  }

  // Helper: formatted progress percentage
  $: progressPercent = getProgressPercent(bytesTransferred, totalBytes);
</script>

<div class="glass-container">
  <!-- Sidebar Navigation -->
  <aside class="sidebar" class:collapsed={sidebarCollapsed}>
    <div class="brand">
      <div class="brand-dot"></div>
      {#if !sidebarCollapsed}
        <span class="brand-name">wisp</span>
      {/if}
    </div>

    <nav class="nav-links">
      <button class="nav-btn" class:active={activeTab === 'dashboard'} on:click={() => activeTab = 'dashboard'} title="Dashboard">
        <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="7" height="9" rx="1" />
          <rect x="14" y="3" width="7" height="5" rx="1" />
          <rect x="14" y="12" width="7" height="9" rx="1" />
          <rect x="3" y="16" width="7" height="5" rx="1" />
        </svg>
        {#if !sidebarCollapsed}
          <span>Dashboard</span>
        {/if}
      </button>

      <button class="nav-btn" class:active={activeTab === 'settings'} on:click={() => activeTab = 'settings'} title="Settings">
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
        {#if !sidebarCollapsed}
          <span>Settings</span>
        {/if}
      </button>
    </nav>

    {#if !sidebarCollapsed}
      <div class="sidebar-device-card">
        <span class="device-label">Local Identity</span>
        <span class="device-name">{myDeviceInfo.friendly_name}</span>
        <span class="device-fp" title={myDeviceInfo.fingerprint}>
          {myDeviceInfo.fingerprint ? myDeviceInfo.fingerprint.substring(0, 16) + '...' : 'Generating Identity...'}
        </span>
      </div>
    {/if}

    <!-- Floating Edge-Grab Retractor Zone -->
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <div class="grab-boundary-zone" on:click={() => sidebarCollapsed = !sidebarCollapsed}></div>
    <button class="floating-toggle-btn" on:click={() => sidebarCollapsed = !sidebarCollapsed} title={sidebarCollapsed ? "Expand" : "Collapse"} aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}>
      <svg width="10" height="10" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" style="transform: rotate({sidebarCollapsed ? 180 : 0}deg); transition: transform 0.3s ease;">
        <polyline points="15 18 9 12 15 6" />
      </svg>
    </button>
  </aside>

  <!-- Main View Area -->
  <main class="main-content">
    {#if activeTab === 'dashboard'}
      {#if incomingPairedFile}
        <div class="paired-incoming-banner">
          <div class="banner-content">
            <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            <div>
              <span class="banner-title">Incoming File Transfer</span>
              <p class="banner-desc">Trusted device <strong>{incomingPairedFile.friendly_name}</strong> wants to send you a file.</p>
            </div>
          </div>
          <div class="banner-actions">
            <button class="banner-btn accept" on:click={acceptIncomingPairedFile}>Accept</button>
            <button class="banner-btn decline" on:click={() => incomingPairedFile = null}>Decline</button>
          </div>
        </div>
      {/if}

      <div class="view-header" style="display: flex; justify-content: space-between; align-items: center; width: 100%;">
        <div>
          <h2>Send & Receive</h2>
          <p>Transfer secure files peer-to-peer without servers</p>
        </div>
        <div class="network-badge" class:relay-mode={!!relayUrl}>
          <div class="badge-dot"></div>
          <span>{relayUrl ? 'Relay Active' : 'LAN Only'}</span>
        </div>
      </div>

      {#if transferState === 'idle'}
        <!-- Drag & Drop Zone / Send Picker -->
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div 
          class="drop-zone" 
          class:dragging={isDragging}
          on:dragover={handleDragOver}
          on:dragleave={handleDragLeave}
          on:drop={handleDrop}
          on:click={handleSend}
        >
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
              on:keydown={(e) => e.key === 'Enter' && handleReceive()}
            />
            <button class="btn-primary" on:click={handleReceive}>Receive</button>
          </div>
        </div>

        <!-- LAN Devices Peer Discovery Dashboard -->
        <div class="lan-dashboard">
          <div style="display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 12px;">
            <span class="drop-subtext" style="text-transform: uppercase; font-weight: 600; margin: 0;">LAN Devices</span>
            <button class="link-btn" on:click={() => { showPairingModal = true; pairingTargetPeer = null; pairingMode = 'idle'; pairingCodeInput = ''; }}>+ Pair Device</button>
          </div>

          <div class="peer-grid">
            <!-- Discovered Online Devices -->
            {#each discoveredPeers as peer}
              {@const isTrusted = trustedPeers.some(tp => tp.certificate_fingerprint === peer.fingerprint)}
              <div class="peer-card">
                <div class="peer-header">
                  <div class="peer-status online"></div>
                  <span class="peer-name">{peer.friendly_name}</span>
                </div>
                <span class="peer-address">{peer.address}</span>
                <div class="peer-actions">
                  {#if isTrusted}
                    <button class="peer-action-btn send" on:click={() => directSendToPeer(trustedPeers.find(tp => tp.certificate_fingerprint === peer.fingerprint))}>Send File</button>
                  {:else}
                    <button class="peer-action-btn pair" on:click={() => { pairingTargetPeer = peer; showPairingModal = true; pairingMode = 'idle'; pairingCodeInput = ''; }}>Pair Device</button>
                  {/if}
                </div>
              </div>
            {/each}

            <!-- Trusted Peers Offline List -->
            {#each trustedPeers as trusted}
              {@const isOnline = discoveredPeers.some(p => p.fingerprint === trusted.certificate_fingerprint)}
              {#if !isOnline}
                <div class="peer-card offline">
                  <div class="peer-header">
                    <div class="peer-status offline"></div>
                    <span class="peer-name">{trusted.friendly_name}</span>
                  </div>
                  <span class="peer-address">Offline</span>
                  <div class="peer-actions">
                    <button class="peer-action-btn delete" on:click={() => deletePeer(trusted.certificate_fingerprint)}>Forget</button>
                  </div>
                </div>
              {/if}
            {/each}

            {#if discoveredPeers.length === 0 && trustedPeers.length === 0}
              <div class="lan-empty-state">
                <svg width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
                  <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14h-2v-2h2zm0-4h-2V7h2z" />
                </svg>
                <span>No local devices found. Make sure devices are connected to the same Wi-Fi.</span>
              </div>
            {/if}
          </div>
        </div>

        {#if showPairingModal}
          <!-- svelte-ignore a11y-click-events-have-key-events -->
          <!-- svelte-ignore a11y-no-static-element-interactions -->
          <div class="modal-backdrop" on:click={() => showPairingModal = false}>
            <div class="modal-content glass-card" on:click|stopPropagation>
              <div class="modal-header">
                <h3>Pair Local Device</h3>
                <button class="close-btn" on:click={() => showPairingModal = false}>&times;</button>
              </div>

              <div class="modal-body">
                {#if pairingTargetPeer}
                  <!-- Connecting mode: Client connecting to target peer -->
                  <div class="modal-step">
                    <span class="step-label">Pairing with {pairingTargetPeer.friendly_name}</span>
                    <p class="step-desc">Enter the 6-digit pairing code displayed on the other device's screen:</p>
                    
                    {#if pairingMode === 'idle' || pairingMode === 'connecting'}
                      <div class="code-row" style="margin-top: 12px;">
                        <input 
                          type="text" 
                          class="input-glow center-align" 
                          placeholder="e.g. 7-tiger-saturn" 
                          bind:value={pairingCodeInput} 
                        />
                        <button class="btn-primary" on:click={connectPairing} disabled={pairingMode === 'connecting'}>
                          {pairingMode === 'connecting' ? 'Connecting...' : 'Connect'}
                        </button>
                      </div>
                    {:else if pairingMode === 'success'}
                      <div class="pairing-status success">
                        <svg width="24" height="24" fill="none" stroke="var(--accent-sage)" stroke-width="2.5" viewBox="0 0 24 24">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                        <span>Devices Successfully Paired!</span>
                      </div>
                    {:else if pairingMode === 'error'}
                      <div class="pairing-status error">
                        <span style="color: var(--accent-coral);">{errorMessage}</span>
                        <button class="btn-primary" style="margin-top: 12px;" on:click={() => pairingMode = 'idle'}>Retry</button>
                      </div>
                    {/if}
                  </div>
                {:else}
                  <!-- Hosting mode: Generate pairing code for others to enter -->
                  <div class="modal-step">
                    <span class="step-label">Generate Pairing Code</span>
                    <p class="step-desc">Share this code with the peer device to establish a trust relationship:</p>
                    
                    {#if pairingMode === 'idle' || pairingMode === 'hosting'}
                      <button class="btn-primary" style="margin: 16px 0;" on:click={hostPairing} disabled={pairingMode === 'hosting'}>
                        {pairingMode === 'hosting' ? 'Awaiting Connection...' : 'Generate Code & Host'}
                      </button>
                      
                      {#if pairingMode === 'hosting'}
                        <div class="pairing-code" style="font-size: 24px; justify-content: center; margin: 12px 0;">
                          {pairingCodeInput}
                        </div>
                        <span class="waiting-sub">Awaiting peer validation request...</span>
                      {/if}
                    {:else if pairingMode === 'success'}
                      <div class="pairing-status success">
                        <svg width="24" height="24" fill="none" stroke="var(--accent-sage)" stroke-width="2.5" viewBox="0 0 24 24">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                        <span>Devices Successfully Paired!</span>
                      </div>
                    {:else if pairingMode === 'error'}
                      <div class="pairing-status error">
                        <span style="color: var(--accent-coral);">{errorMessage}</span>
                        <button class="btn-primary" style="margin-top: 12px;" on:click={() => pairingMode = 'idle'}>Retry</button>
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            </div>
          </div>
        {/if}

      {:else if transferState === 'waiting'}
        <!-- Waiting on peer to connect screen -->
        <div class="code-present-container">
          <span class="present-label">Your Pairing Code</span>
          <!-- svelte-ignore a11y-click-events-have-key-events -->
          <!-- svelte-ignore a11y-no-static-element-interactions -->
          <div class="pairing-code" on:click={copyCodeToClipboard}>
            {pairingCode}
            {#if copied}
              <svg width="16" height="16" fill="none" stroke="var(--accent-sage)" stroke-width="2.5" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            {:else}
              <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
              </svg>
            {/if}
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
