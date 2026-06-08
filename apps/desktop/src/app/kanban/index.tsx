import { useStore } from '@nanostores/react'
import { useEffect, useMemo, useRef, useState } from 'react'

import { Button } from '@/components/ui/button'
import { Codicon } from '@/components/ui/codicon'
import { $activeGatewayProfile, normalizeProfileKey } from '@/store/profile'

const KEEPALIVE_MS = 60_000

type KanbanWebview = HTMLElement & {
  getURL?: () => string
  reload?: () => void
}

function dashboardPath(baseUrl: string, path: string): string {
  const url = new URL(baseUrl)
  const basePath = url.pathname.replace(/\/+$/, '')
  url.pathname = `${basePath}${path.startsWith('/') ? path : `/${path}`}`
  url.search = ''
  url.hash = ''

  return url.toString()
}

export function KanbanView() {
  const activeProfile = useStore($activeGatewayProfile)
  const kanbanProfile = normalizeProfileKey(activeProfile)
  const hostRef = useRef<HTMLDivElement | null>(null)
  const webviewRef = useRef<KanbanWebview | null>(null)
  const [targetUrl, setTargetUrl] = useState<string | null>(null)
  const [partition, setPartition] = useState('persist:hermes-kanban')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    setLoading(true)
    setError(null)
    setTargetUrl(null)

    void window.hermesDesktop
      .getConnection(kanbanProfile)
      .then(conn => {
        if (cancelled) {
          return
        }

        setPartition(conn.authMode === 'oauth' ? 'persist:hermes-remote-oauth' : 'persist:hermes-kanban')
        setTargetUrl(dashboardPath(conn.baseUrl, '/kanban'))
      })
      .catch(err => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err))
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [kanbanProfile])

  useEffect(() => {
    void window.hermesDesktop?.touchBackend?.(kanbanProfile).catch(() => undefined)

    const timer = window.setInterval(() => {
      void window.hermesDesktop?.touchBackend?.(kanbanProfile).catch(() => undefined)
    }, KEEPALIVE_MS)

    return () => window.clearInterval(timer)
  }, [kanbanProfile])

  useEffect(() => {
    const host = hostRef.current

    if (!host || !targetUrl) {
      return
    }

    host.textContent = ''

    const webview = document.createElement('webview') as KanbanWebview
    webview.className = 'h-full w-full flex-1 bg-(--ui-chat-surface-background)'
    webview.setAttribute('partition', partition)
    webview.setAttribute('src', targetUrl)
    webview.setAttribute('webpreferences', 'contextIsolation=yes,nodeIntegration=no,sandbox=yes')

    const markLoaded = () => {
      setLoading(false)
      setError(null)
    }

    const markFailed = (event: Event) => {
      const detail = (event as CustomEvent<{ errorDescription?: string }>).detail

      setLoading(false)
      setError(detail?.errorDescription || 'Kanban failed to load.')
    }

    webview.addEventListener('did-finish-load', markLoaded)
    webview.addEventListener('did-fail-load', markFailed)
    host.appendChild(webview)
    webviewRef.current = webview

    return () => {
      webview.removeEventListener('did-finish-load', markLoaded)
      webview.removeEventListener('did-fail-load', markFailed)

      if (webviewRef.current === webview) {
        webviewRef.current = null
      }

      webview.remove()
    }
  }, [partition, targetUrl])

  const openLabel = useMemo(() => {
    if (!targetUrl) {
      return 'Open'
    }

    try {
      return new URL(targetUrl).host
    } catch {
      return 'Open'
    }
  }, [targetUrl])

  const reload = () => {
    setLoading(true)
    setError(null)
    webviewRef.current?.reload?.()
  }

  const openExternal = () => {
    if (targetUrl) {
      void window.hermesDesktop?.openExternal?.(targetUrl)
    }
  }

  return (
    <section className="flex h-full min-w-0 flex-col overflow-hidden bg-(--ui-chat-surface-background)">
      <div className="flex shrink-0 items-center gap-2 border-b border-(--ui-stroke-secondary) px-3 pb-2 pt-[calc(var(--titlebar-height)+0.5rem)]">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Codicon className="text-(--ui-text-tertiary)" name="project" size="0.875rem" />
          <div className="min-w-0 truncate text-[0.8125rem] font-medium text-(--ui-text-primary)">Kanban</div>
          <div className="hidden min-w-0 truncate text-[0.75rem] text-(--ui-text-tertiary) sm:block">
            {targetUrl ? `${kanbanProfile} - ${openLabel}` : kanbanProfile}
          </div>
        </div>
        <Button disabled={!targetUrl} onClick={reload} size="sm" type="button" variant="ghost">
          <Codicon name="refresh" size="0.875rem" spinning={loading} />
          Refresh
        </Button>
        <Button disabled={!targetUrl} onClick={openExternal} size="sm" type="button" variant="ghost">
          <Codicon name="link-external" size="0.875rem" />
          Browser
        </Button>
      </div>

      <div className="relative min-h-0 flex-1 overflow-hidden">
        <div className="h-full w-full" ref={hostRef} />
        {(loading || error) && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center bg-(--ui-chat-surface-background)/80">
            <div className="flex items-center gap-2 text-[0.8125rem] text-(--ui-text-tertiary)">
              <Codicon name={error ? 'warning' : 'loading'} size="0.875rem" spinning={!error} />
              <span>{error || 'Loading Kanban…'}</span>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
