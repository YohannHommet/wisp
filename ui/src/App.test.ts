import { render, fireEvent, screen } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from './App.svelte';

// Mock Navigator Clipboard API
const mockClipboardWriteText = vi.fn().mockResolvedValue(undefined);
Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: mockClipboardWriteText,
  },
  writable: true,
});

describe('Wisp Desktop Svelte App Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders brand identity and default dashboard state', () => {
    render(App);

    // Sidebar branding check
    expect(screen.getByText('wisp')).toBeDefined();
    
    // Main heading check
    expect(screen.getByText('Send & Receive')).toBeDefined();
    expect(screen.getByText('Transfer secure files peer-to-peer without servers')).toBeDefined();
    
    // Dropzone check
    expect(screen.getByText('Drag and drop file here or browse')).toBeDefined();
    
    // Receive input section check
    expect(screen.getByText('Receive File from Peer')).toBeDefined();
    expect(screen.getByPlaceholderText('Enter pairing code...')).toBeDefined();
  });

  it('navigates between dashboard and settings tabs', async () => {
    render(App);

    // Get settings nav button and click it
    const settingsBtn = screen.getByText('Settings');
    await fireEvent.click(settingsBtn);

    // Verify settings tab content is displayed
    expect(screen.getByText('Configure network interfaces and relay nodes')).toBeDefined();
    expect(screen.getByText('Relay Server URL')).toBeDefined();
    expect(screen.getByPlaceholderText('e.g. https://relay.wisp.net')).toBeDefined();
    expect(screen.getByText('Connection Security')).toBeDefined();

    // Navigate back to Dashboard
    const dashboardBtn = screen.getByText('Dashboard');
    await fireEvent.click(dashboardBtn);

    // Verify back on main dashboard
    expect(screen.getByText('Transfer secure files peer-to-peer without servers')).toBeDefined();
  });

  it('handles send file click, enters waiting state and shows pairing code', async () => {
    render(App);

    const dropZone = screen.getByText('Drag and drop file here or browse');
    
    // Simulate dropzone click (which in mocks selects file and generates pairing code)
    await fireEvent.click(dropZone);

    // Check transition to Waiting state
    expect(screen.getByText('Your Pairing Code')).toBeDefined();
    
    // Verify mock pairing code is displayed
    const codeDisplay = screen.getByText('7-tiger-saturn');
    expect(codeDisplay).toBeDefined();
    expect(screen.getByText('Awaiting peer connection...')).toBeDefined();

    // Verify clipboard copying triggers on click
    await fireEvent.click(codeDisplay);
    expect(mockClipboardWriteText).toHaveBeenCalledWith('7-tiger-saturn');
  });

  it('handles receive file input flow with default parameters', async () => {
    render(App);

    const input = screen.getByPlaceholderText('Enter pairing code...');
    const receiveBtn = screen.getByText('Receive');

    // Type pairing code
    await fireEvent.input(input, { target: { value: '9-bear-mars' } });
    
    // Click receive (initiates directory prompt and connects)
    await fireEvent.click(receiveBtn);

    // Verifies transition to active transfer state in mocks
    expect(screen.getByText('Cancel Transfer')).toBeDefined();
  });

  it('cancels active transfer and resets to idle dashboard', async () => {
    render(App);

    // Enter active transfer state
    const input = screen.getByPlaceholderText('Enter pairing code...');
    const receiveBtn = screen.getByText('Receive');
    await fireEvent.input(input, { target: { value: '9-bear-mars' } });
    await fireEvent.click(receiveBtn);

    // Locate and click cancel
    const cancelBtn = screen.getByText('Cancel Transfer');
    await fireEvent.click(cancelBtn);

    // Verify returned to main dashboard
    expect(screen.getByText('Drag and drop file here or browse')).toBeDefined();
  });
});
