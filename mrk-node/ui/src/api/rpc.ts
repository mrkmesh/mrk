import { reactive } from 'vue'

interface PendingCall {
  resolve: (value: unknown) => void
  reject: (reason: Error) => void
  timer: number
}

interface RpcEnvelope {
  id: number
  result?: unknown
  error?: { code: string; message: string }
}

export const rpcState = reactive({
  status: 'connecting' as 'connecting' | 'connected' | 'disconnected',
})

let socket: WebSocket | null = null
let nextId = 1
let reconnectTimer: number | null = null
const pending = new Map<number, PendingCall>()

function endpoint(): string {
  const configured = import.meta.env.VITE_RPC_ENDPOINT as string | undefined
  if (configured) return configured
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${location.host}/v1/rpc`
}

function connect(): Promise<WebSocket> {
  if (socket?.readyState === WebSocket.OPEN) return Promise.resolve(socket)
  if (socket?.readyState === WebSocket.CONNECTING) {
    return new Promise((resolve, reject) => {
      socket?.addEventListener('open', () => resolve(socket as WebSocket), { once: true })
      socket?.addEventListener('error', () => reject(new Error('Unable to connect to this node')), { once: true })
    })
  }

  rpcState.status = 'connecting'
  socket = new WebSocket(endpoint(), 'mrk.rpc.v1')
  socket.binaryType = 'arraybuffer'
  socket.addEventListener('open', () => {
    rpcState.status = 'connected'
  })
  socket.addEventListener('message', async (event) => {
    const text = typeof event.data === 'string'
      ? event.data
      : new TextDecoder().decode(event.data instanceof Blob ? await event.data.arrayBuffer() : event.data)
    const response = JSON.parse(text) as RpcEnvelope
    const call = pending.get(response.id)
    if (!call) return
    pending.delete(response.id)
    window.clearTimeout(call.timer)
    if (response.error) call.reject(new Error(response.error.message))
    else call.resolve(response.result)
  })
  socket.addEventListener('close', () => {
    socket = null
    rpcState.status = 'disconnected'
    for (const [id, call] of pending) {
      window.clearTimeout(call.timer)
      call.reject(new Error('Connection to this node was interrupted'))
      pending.delete(id)
    }
    if (reconnectTimer === null) {
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null
        void connect().catch(() => undefined)
      }, 2_000)
    }
  })
  return new Promise((resolve, reject) => {
    socket?.addEventListener('open', () => resolve(socket as WebSocket), { once: true })
    socket?.addEventListener('error', () => reject(new Error('Unable to connect to this node')), { once: true })
  })
}

export async function rpc<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const active = await connect()
  const id = nextId++
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      pending.delete(id)
      reject(new Error('The node did not answer in time'))
    }, 15_000)
    pending.set(id, {
      resolve: (value) => resolve(value as T),
      reject,
      timer,
    })
    active.send(new TextEncoder().encode(JSON.stringify({ id, method, params })))
  })
}
