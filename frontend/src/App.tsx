import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { MetricsOverview } from './components/MetricsOverview';
import { LiveTrafficMonitor } from './components/LiveTrafficMonitor';
import { PhishingAnalyzer } from './components/PhishingAnalyzer';
import { MalwareBehaviorSandbox } from './components/MalwareBehaviorSandbox';
import { AiSocAssistant } from './components/AiSocAssistant';
import { ThreatIntelligenceMap } from './components/ThreatIntelligenceMap';
import { AlertNotificationCenter } from './components/AlertNotificationCenter';
import { NetworkFlow, NetworkStats, SecurityAlert, WebSocketTelemetryPayload } from './types';
import { api } from './services/api';
import { useTelemetryWebSocket } from './hooks/useTelemetryWebSocket';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [stats, setStats] = useState<NetworkStats | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [activeSimulation, setActiveSimulation] = useState<string | null>(null);

  // WebSocket message handler
  const handleWsMessage = useCallback((data: WebSocketTelemetryPayload) => {
    if (data.type === 'TRAFFIC_UPDATE') {
      if (data.flow) {
        setFlows(prev => [data.flow!, ...prev.slice(0, 75)]);
      }
      if (data.stats) {
        setStats(data.stats);
        setActiveSimulation(data.stats.active_simulation);
      }
      if (data.alert) {
        setAlerts(prev => [data.alert!, ...prev]);
      }
    }
  }, []);

  // Connect telemetry WebSocket with resilient reconnection
  useTelemetryWebSocket({ onMessage: handleWsMessage });

  // Initial Data Fetch
  useEffect(() => {
    api.getRecentTraffic()
      .then(res => {
        if (res.flows) setFlows(res.flows.slice().reverse());
        if (res.stats) setStats(res.stats);
      })
      .catch(err => console.error('Error fetching initial traffic:', err));

    api.getAlerts()
      .then(res => {
        if (res.alerts) setAlerts(res.alerts);
      })
      .catch(err => console.error('Error fetching initial alerts:', err));
  }, []);

  const handleSimulateAttack = async (type: string | null) => {
    setActiveSimulation(type);
    try {
      await api.simulateAttack(type);
    } catch (e) {
      console.error('Failed to trigger attack simulation:', e);
    }
  };

  const handleRefreshAlerts = () => {
    api.getAlerts()
      .then(res => {
        if (res.alerts) setAlerts(res.alerts);
      })
      .catch(err => console.error('Error refreshing alerts:', err));
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
