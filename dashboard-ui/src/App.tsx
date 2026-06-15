import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./layout/AppLayout";
import { DashboardPage } from "./pages/DashboardPage";
import { DebateProcessPage } from "./pages/DebateProcessPage";
import { EventDetailPage } from "./pages/EventDetailPage";
import { EventListPage } from "./pages/EventListPage";
import { OpsAgentPage } from "./pages/OpsAgentPage";
import { StrategyExecutionPage } from "./pages/StrategyExecutionPage";
import { SystemStatusPage } from "./pages/SystemStatusPage";
import { TasksPage } from "./pages/TasksPage";

export function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/events" element={<EventListPage />} />
        <Route path="/events/:id" element={<EventDetailPage />} />
        <Route path="/debate" element={<DebateProcessPage />} />
        <Route path="/executions" element={<StrategyExecutionPage />} />
        <Route path="/ops" element={<OpsAgentPage />} />
        <Route path="/system" element={<SystemStatusPage />} />
        <Route path="/tasks" element={<TasksPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}
