import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/auth";
import { Spinner } from "./components/ui";
import DashboardLayout from "./layouts/DashboardLayout";
import Login from "./pages/Login";
import CommandCenter from "./pages/CommandCenter";
import FileIntelligence from "./pages/FileIntelligence";
import CanaryManagement from "./pages/CanaryManagement";
import ProcessIntelligence from "./pages/ProcessIntelligence";
import ThreatDetection from "./pages/ThreatDetection";
import IncidentResponse from "./pages/IncidentResponse";
import Forensics from "./pages/Forensics";
import SettingsPage from "./pages/Settings";

function Protected({ children }: { children: JSX.Element }) {
  const { user, ready } = useAuth();
  if (!ready) return <div className="min-h-screen grid place-items-center"><Spinner /></div>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function Shell() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Protected><DashboardLayout /></Protected>}>
        <Route index element={<CommandCenter />} />
        <Route path="files" element={<FileIntelligence />} />
        <Route path="canaries" element={<CanaryManagement />} />
        <Route path="processes" element={<ProcessIntelligence />} />
        <Route path="threats" element={<ThreatDetection />} />
        <Route path="incidents" element={<IncidentResponse />} />
        <Route path="incidents/:id" element={<IncidentResponse />} />
        <Route path="forensics" element={<Forensics />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  );
}
