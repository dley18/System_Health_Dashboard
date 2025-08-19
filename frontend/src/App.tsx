import { useEffect, useRef, useState } from "react";

function useMetricsWS(url: string) {
  const [cpu, setCpu] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let stopped = false;
    const connect = () => {
      const ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        const data = JSON.parse(ev.data);
        if (data?.cpu?.total != null) setCpu(data.cpu.total);
      };
      ws.onclose = () => {
        if (!stopped) setTimeout(connect, 1000); // simple reconnect
      };
    };
    connect();
    return () => {
      stopped = true;
      wsRef.current?.close();
    };
  }, [url]);

  return cpu;
}

export default function App() {
  const cpu = useMetricsWS("ws://localhost:8000/metrics/stream");
  return (
    <div style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1>PC Health Dashboard (MVP)</h1>
      <p>Status: {cpu == null ? "Connecting..." : "Live"}</p>
      <div style={{ fontSize: 48, fontWeight: 700 }}>
        CPU: {cpu == null ? "—" : `${cpu.toFixed(1)}%`}
      </div>
      <p style={{ opacity: 0.7 }}>Next: add charts & more metrics.</p>
    </div>
  );
}
