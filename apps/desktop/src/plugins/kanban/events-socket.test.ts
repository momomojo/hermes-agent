/**
 * The Kanban events socket starts at the current event and resumes from its
 * last stream cursor on reconnect, per backend.
 *
 * A fresh stream asks for `since=latest` (a full replay of `task_events`
 * saturated the backend); the server answers with an opening cursor frame. A
 * reconnect sends the last cursor it saw as `?since=`, or every event raised
 * while the socket was down (completions, blockers) would be skipped. Event ids
 * are local to one backend, so a reconnect that lands on another profile or
 * connection starts that backend's own stream. A board switch starts fresh.
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
  closed: boolean
  onMessage: OnMessage
  path: (backend: string) => string
}

function fakeSocketDoor() {
  const opened: OpenedSocket[] = []

  const socket = (path: string | ((backend: string) => string), onMessage: OnMessage) => {
    const entry: OpenedSocket = {
      closed: false,
      onMessage,
      path: typeof path === 'function' ? path : () => path
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
  it('asks for the latest event without a cursor, and resumes with one', async () => {
    const { eventsPath } = await import('./api')

    expect(eventsPath('', null)).toBe('/events?since=latest')
    expect(eventsPath('main board', null)).toBe('/events?board=main+board&since=latest')
    expect(eventsPath('ops', 42)).toBe('/events?board=ops&since=42')
    expect(eventsPath('', 0)).toBe('/events?since=0')
  })
})

describe('bindApi events socket', () => {
  beforeEach(() => {
    vi.resetModules()
    invalidateQueries.mockClear()
    hostMock.notify.mockClear()
  })

  it('reconnects from the last cursor it saw, including the opening frame', async () => {
    const { bindApi } = await import('./api')
    const { opened, socket } = fakeSocketDoor()
    const dispose = bindApi(rest, storage(), socket)

    expect(opened).toHaveLength(1)
    // First connection: no cursor yet, so start at the current event.
    expect(opened[0].path('backend-a')).toBe('/events?since=latest')

    // The server's opening frame announces where the stream starts.
    opened[0].onMessage({ events: [], cursor: 42 })
    expect(opened[0].path('backend-a')).toBe('/events?since=42')

    // Later frames advance it; a reconnect re-evaluates the path.
    opened[0].onMessage({ events: [{ id: 43, kind: 'created', task_id: 't1' }], cursor: 43 })
    expect(opened[0].path('backend-a')).toBe('/events?since=43')

    // A stale or malformed cursor never moves it backwards.
    opened[0].onMessage({ events: [], cursor: 7 })
    opened[0].onMessage({ events: [], cursor: 'x' })
    expect(opened[0].path('backend-a')).toBe('/events?since=43')

    dispose()
  })

  it('keeps one cursor per backend across a profile or connection switch', async () => {
    const { bindApi } = await import('./api')
    const { opened, socket } = fakeSocketDoor()
    const dispose = bindApi(rest, storage(), socket)

    expect(opened[0].path('backend-a')).toBe('/events?since=latest')
    opened[0].onMessage({ events: [], cursor: 500 })

    // A reconnect that lands on another backend must not send A's cursor.
    expect(opened[0].path('backend-b')).toBe('/events?since=latest')
    opened[0].onMessage({ events: [], cursor: 7 })
    expect(opened[0].path('backend-b')).toBe('/events?since=7')

    // Returning to A resumes A's own stream.
    expect(opened[0].path('backend-a')).toBe('/events?since=500')

    dispose()
  })

  it('counts notifications from the opening cursor, so the first live event notifies', async () => {
    // /board already counts event 101 when a lazy baseline would be fetched.
    const restAt101 = vi.fn(async () => ({ latest_event_id: 101 })) as unknown as <T>(path: string) => Promise<T>
    const { $boardSlug, bindApi } = await import('./api')
    const { opened, socket } = fakeSocketDoor()
    const dispose = bindApi(restAt101, storage(), socket)

    $boardSlug.set('ops')
    const live = opened[1]

    expect(live.path('backend-a')).toBe('/events?board=ops&since=latest')
    live.onMessage({ events: [], cursor: 100 })
    live.onMessage({
      cursor: 101,
      events: [{ id: 101, kind: 'completed', payload: { summary: 'Done' }, task_id: 't1' }]
    })

    await vi.waitFor(() => expect(hostMock.notify).toHaveBeenCalledTimes(1))

    dispose()
  })

  it('starts a fresh stream when the board changes', async () => {
    const { $boardSlug, bindApi } = await import('./api')
    const { opened, socket } = fakeSocketDoor()
    const dispose = bindApi(rest, storage(), socket)

    expect(opened[0].path('backend-a')).toBe('/events?since=latest')
    opened[0].onMessage({ events: [], cursor: 42 })
    $boardSlug.set('ops')

    expect(opened).toHaveLength(2)
    expect(opened[0].closed).toBe(true)
    expect(opened[1].path('backend-a')).toBe('/events?board=ops&since=latest')

    dispose()
  })
})
