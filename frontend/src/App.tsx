import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { MetricsOverview } from './components/MetricsOverview';
import { LiveTrafficMonitor } from './components/LiveTrafficMonitor';
import { PhishingAnalyzer } from './components/PhishingAnalyzer';
import { MalwareBehaviorSandbox } from './components/MalwareBehaviorSandbox';
import { AiSocAssistant } from './components/AiSocAssistant';
import { ThreatIntelligenceMap } from './components/ThreatIntelligenceMap';
import { AlertNotificationCenter } from './components/AlertNotificationCenter';
import { NetworkFlow, NetworkStats, SecurityAlert } from './types';
import { api } from './services/api';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);

  // Initial Fetch & WebSocket Connection
  useEffect(() => {
    // 1. Initial REST fetch for immediate render
    api.getRecentTraffic().then(res => {
      if (res.flows) setFlows(res.flows.reverse());
      if (res.stats) setStats(res.stats);
    }).catch(console.error);

    api.getAlerts().then(res => {
      if (res.alerts) setAlerts(res.alerts);
    }).catch(console.error);

    // 2. WebSocket Telemetry Stream
    let socket: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connectWebSocket = () => {
      try {
        socket = new WebSocket('ws://localhost:8000/ws/telemetry');
        socket.onopen = () => {
          console.log('Connected to CyberSentinel Live Telemetry WebSocket');
        };

        socket.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'TRAFFIC_UPDATE') {
              if (data.flow) {
                setFlows(prev => [data.flow, ...prev.slice(0, 75)]);
              }
              if (data.stats) {
                setStats(data.stats);
                setActiveSimulation(data.stats.active_simulation);
              }
              if (data.alert) {
                setAlerts(prev => [data.alert, ...prev]);
              }
            }
          } catch (err) {
            console.error('Error parsing WS message:', err);
          }
        };

        socket.onclose = () => {
          console.log('Telemetry WebSocket closed. Reconnecting in 3s...');
          reconnectTimeout = setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = (err) => {
          console.warn('WebSocket connection error, falling back to polling if necessary.');
        };
      } catch (err) {
        console.error('WS init error:', err);
      }
    };

    connectWebSocket();

    return () => {
      if (socket) socket.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  const handleSimulateAttack = async (type: string | null) => {
    setActiveSimulation(type);
    try {
      await api.simulateAttack(type);
    } catch (e) {
      console.error(e);
    }
  };

  const handleRefreshAlerts = () => {
    api.getAlerts().then(res => {
      if (res.alerts) setAlerts(res.alerts);
    }).catch(console.error);
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans">
      <Navbar
        stats={stats}
        onSimulateAttack={handleSimulateAttack}
        activeSimulation={activeSimulation}
      />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          currentTab={currentTab}
          onTabChange={setCurrentTab}
          alertCount={alerts.filter(a => a.status === 'OPEN').length}
        />

        <main className="flex-1 overflow-y-auto p-6 space-y-6 cyber-grid-bg">
          {currentTab === 'overview' && (
            <div className="space-y-6">
              <MetricsOverview stats={stats} totalAlerts={alerts.length} />
              
              <div className="grid grid-cols-1 gap-6">
                <LiveTrafficMonitor
                  flows={flows}
                  onSimulateAttack={handleSimulateAttack}
                  activeSimulation={activeSimulation}
                  onInspectFlow={() => {}}
                />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <AlertNotificationCenter
                  alerts={alerts.slice(0, 5)}
                  onRefreshAlerts={handleRefreshAlerts}
                />
                <ThreatIntelligenceMap />
              </div>
            </div>
          )}

          {currentTab === 'traffic' && (
            <LiveTrafficMonitor
              flows={flows}
              onSimulateAttack={handleSimulateAttack}
              activeSimulation={activeSimulation}
              onInspectFlow={() => {}}
            />
          )}

          {currentTab === 'phishing' && (
            <PhishingAnalyzer />
          )}

          {currentTab === 'malware' && (
            <MalwareBehaviorSandbox />
          )}

          {currentTab === 'incidents' && (
            <AiSocAssistant />
          )}

          {currentTab === 'intel' && (
            <ThreatIntelligenceMap />
          )}

          {currentTab === 'alerts' && (
            <AlertNotificationCenter
              alerts={alerts}
              onRefreshAlerts={handleRefreshAlerts}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
