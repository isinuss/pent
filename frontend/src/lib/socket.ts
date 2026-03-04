import { io, Socket } from 'socket.io-client';
import { getToken } from './api';

export interface ScanOutputEvent {
  scan_id: string;
  line: string;
}

export interface ScanStatusEvent {
  scan_id: string;
  status: string;
  finding_count?: number;
}

let socket: Socket | null = null;

export function getSocket(): Socket {
  if (!socket) {
    socket = io('/', {
      path: '/socket.io',
      transports: ['websocket', 'polling'],
      auth: {
        token: getToken(),
      },
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
    });

    socket.on('connect', () => {
      console.log('[socket] connected:', socket?.id);
    });

    socket.on('disconnect', (reason) => {
      console.log('[socket] disconnected:', reason);
    });

    socket.on('connect_error', (err) => {
      console.error('[socket] connection error:', err.message);
    });
  }

  return socket;
}

export function subscribeScan(
  scanId: string,
  onOutput: (data: ScanOutputEvent) => void,
  onStatus: (data: ScanStatusEvent) => void
): () => void {
  const s = getSocket();

  s.emit('subscribe', { scan_id: scanId });

  const handleOutput = (data: ScanOutputEvent) => {
    if (data.scan_id === scanId) {
      onOutput(data);
    }
  };

  const handleStatus = (data: ScanStatusEvent) => {
    if (data.scan_id === scanId) {
      onStatus(data);
    }
  };

  s.on('scan_output', handleOutput);
  s.on('scan_status', handleStatus);

  return () => {
    s.off('scan_output', handleOutput);
    s.off('scan_status', handleStatus);
    s.emit('unsubscribe', { scan_id: scanId });
  };
}

export function disconnectSocket(): void {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
}
