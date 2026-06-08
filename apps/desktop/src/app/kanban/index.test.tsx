import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { $activeGatewayProfile } from '@/store/profile'

import { KanbanView } from './index'

const getConnection = vi.fn()
const touchBackend = vi.fn()
const openExternal = vi.fn()

function installDesktopBridge(): void {
  Object.defineProperty(window, 'hermesDesktop', {
    configurable: true,
    value: {
      getConnection,
      openExternal,
      touchBackend
    } as unknown as Window['hermesDesktop']
  })
}

beforeEach(() => {
  $activeGatewayProfile.set('default')
  getConnection.mockImplementation(async (profile: string) => ({
    authMode: 'token',
    baseUrl: `http://${profile}.example.test/root/`,
    isFullscreen: false,
    logs: [],
    nativeOverlayWidth: 0,
    token: '',
    windowButtonPosition: null,
    wsUrl: `ws://${profile}.example.test/ws`
  }))
  touchBackend.mockResolvedValue({ ok: true })
  installDesktopBridge()
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
  $activeGatewayProfile.set('default')
})

describe('KanbanView', () => {
  it('loads and keeps alive the active gateway profile backend', async () => {
    $activeGatewayProfile.set('nas-ops')

    render(<KanbanView />)

    await waitFor(() => expect(getConnection).toHaveBeenCalledWith('nas-ops'))
    await waitFor(() => expect(touchBackend).toHaveBeenCalledWith('nas-ops'))
    expect(await screen.findByText('nas-ops - nas-ops.example.test')).toBeTruthy()
  })
})
