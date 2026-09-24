/**
 * The Kanban events socket resumes from its last stream cursor on reconnect.
 *
 * The server starts a cursorless socket at the current event (a full replay of
 * `task_events` saturated the backend), and announces that starting cursor in
 * an opening frame. A reconnect must send the last cursor it saw as `?since=`,
 * or every event raised while the socket was down (completions, blockers) would
 * be skipped. A board switch opens a fresh stream with no cursor.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'

const { hostMock, invalidateQueries } = vi.hoisted(() => ({
  hostMock: { notify: vi.fn(), navigate: vi.fn() },
  invalidateQueries: vi.fn()
}))

vi.mock('@hermes/plugin-sdk', () => {
  // Minimal nanostore-shaped atom: get/set/listen.
  const atom = <T>(initial: T) => {
    let value = initial
    const listeners = new Set<(v: T) => void>()

    return {
      get: () => value,
      set: (next: T) => {
        value = next
        listeners.forEach(cb => cb(next))
      },
      listen: (cb: (v: T) => void) => {
        listeners.add(cb)

        return () => listeners.delete(cb)
      }
    }
  }

  return {
    atom,
    host: hostMock,
    queryClient: { invalidateQueries },
    usePluginI18n: () => (key: string) => key
  }
})

type OnMessage = (data: unknown) => void

interface OpenedSocket {
  path: () => string
  onMessage: OnMessage
  closed: boolean
}

function fakeSocketDoor() {
  const opened: OpenedSocket[] = []

  const socket = (path: string | (() => string), onMessage: OnMessage) => {
    const entry: OpenedSocket = {
      path: typeof path === 'function' ? path : () => path,
      onMessage,
      closed: false
    }

    opened.push(entry)

    return () => {
      entry.closed = true
    }
  }

  return { opened, socket }
}

const storage = () => {
  const data = new Map<string, unknown>()

  return {
    get: <T>(key: string, fallback: T): T => (data.has(key) ? (data.get(key) as T) : fallback),
    set: (key: string, value: unknown) => void data.set(key, value),
    remove: (key: string) => void data.delete(key)
  }
}

const rest = vi.fn(async () => ({ latest_event_id: 0 })) as unknown as <T>(path: string) => Promise<T>

describe('eventsPath', () => {
  it('adds the board and the resume cursor only when present', async () => {
    const { eventsPath } = await import('./api')

    expect(eventsPath('', null)).toBe('/events')
    expect(eventsPath('main board', null)).toBe('/events?board=main+board')
    expect(eventsPath('ops', 42)).toBe('/events?board=ops&since=42')
    expect(eventsPath('', 0)).toBe('/events?since=0')
  })
})

describe('bindApi events socket', () => {
  beforeEach(() => {
    vi.resetModules()
    invalidateQueries.mockClear()
  })

  it('reconnects from the last cursor it saw, including the opening frame', async () => {
    const { bindApi } = await import('./api')
    const { opened, socket } = fakeSocketDoor()
    const dispose = bindApi(rest, storage(), socket)

    expect(opened).toHaveLength(1)
    // First connection: no cursor yet, so the server baselines at "now".
    expect(opened[0].path()).toBe('/events')

    // The server's opening frame announces where the stream starts.
    opened[0].onMessage({ events: [], cursor: 42 })
    expect(opened[0].path()).toBe('/events?since=42')

    // Later frames advance it; a reconnect re-evaluates the path.
    opened[0].onMessage({ events: [{ id: 43, task_id: 't1', kind: 'created' }], cursor: 43 })
    expect(opened[0].path()).toBe('/events?since=43')

    // A stale or malformed cursor never moves it backwards.
    opened[0].onMessage({ events: [], cursor: 7 })
    opened[0].onMessage({ events: [], cursor: 'x' })
    expect(opened[0].path()).toBe('/events?since=43')

    dispose()
  })

  it('starts a fresh stream (no cursor) when the board changes', async () => {
    const { $boardSlug, bindApi } = await import('./api')
    const { opened, socket } = fakeSocketDoor()
    const dispose = bindApi(rest, storage(), socket)

    opened[0].onMessage({ events: [], cursor: 42 })
    $boardSlug.set('ops')

    expect(opened).toHaveLength(2)
    expect(opened[0].closed).toBe(true)
    expect(opened[1].path()).toBe('/events?board=ops')

    dispose()
  })
})
