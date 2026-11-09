import { useEffect, useRef, useState, useCallback } from 'react';
import { WebSocketTelemetryPayload } from '../types';

interface UseTelemetryWebSocketOptions {
  onMessage?: (payload: WebSocketTelemetryPayload) => void;
  reconnectIntervalMs?: number;
}

export function useTelemetryWebSocket(options: UseTelemetryWebSocketOptions = {}) {
  const { onMessage, reconnectIntervalMs = 3000 } = options;
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onMessageRef = useRef(onMessage);

  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  const connect = useCallback(() => {
    if (socketRef.current && (socketRef.current.readyState === WebSocket.OPEN || socketRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const explicitWsUrl = import.meta.env.VITE_WS_URL;
    let wsUrl: string;

    if (explicitWsUrl) {
      wsUrl = explicitWsUrl;
    } else {
      const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
      const host = typeof window !== 'undefined' ? window.location.host : 'localhost:8000';
      const protocol = isHttps ? 'wss:' : 'ws:';
      wsUrl = `${protocol}//${host}/ws/telemetry`;
    }

    try {
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data) as WebSocketTelemetryPayload;
          if (onMessageRef.current) {
            onMessageRef.current(parsed);
          }
        } catch (err) {
          console.warn('Failed to parse incoming telemetry WebSocket message:', err);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        socketRef.current = null;
        reconnectTimerRef.current = setTimeout(connect, reconnectIntervalMs);
      };

      ws.onerror = (err) => {
        console.warn('Telemetry stream connection error, will reconnect...', err);
        ws.close();
      };
    } catch (err) {
      console.warn('Failed to create WebSocket instance:', err);
      reconnectTimerRef.current = setTimeout(connect, reconnectIntervalMs);
    }
  }, [reconnectIntervalMs]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [connect]);

  const sendCommand = useCallback((action: string, payload: Record<string, unknown> = {}) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify({ action, ...payload }));
      return true;
    }
    return false;
  }, []);

  return { isConnected, sendCommand };
}
