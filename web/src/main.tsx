import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { I18nProvider } from "./i18n";
import { Agents } from "./pages/Agents";
import { Audit, Jobs, Members, PolicyPage } from "./pages/Admin";
import { CertificateDetail, CertificateList, NewCertificate } from "./pages/Certificates";
import { Configs } from "./pages/Configs";
import { Discovery } from "./pages/Discovery";
import { Login } from "./pages/Login";
import { Home, OrgOverview } from "./pages/Org";
import { SessionGate } from "./session";
import "./styles.css";

function App() {
  return (
    <SessionGate login={(done) => <Login onDone={done} />}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="o/:org" element={<OrgOverview />} />
          <Route path="o/:org/configs" element={<Configs scope="org" />} />
          <Route path="o/:org/discovery" element={<Discovery />} />
          <Route path="o/:org/members" element={<Members scope="org" />} />
          <Route path="o/:org/audit" element={<Audit />} />
          <Route path="o/:org/p/:project" element={<CertificateList />} />
          <Route path="o/:org/p/:project/certificates/new" element={<NewCertificate />} />
          <Route path="o/:org/p/:project/certificates/:cert" element={<CertificateDetail />} />
          <Route path="o/:org/p/:project/agents" element={<Agents />} />
          <Route path="o/:org/p/:project/configs" element={<Configs scope="project" />} />
          <Route path="o/:org/p/:project/policy" element={<PolicyPage />} />
          <Route path="o/:org/p/:project/members" element={<Members scope="project" />} />
          <Route path="o/:org/p/:project/jobs" element={<Jobs />} />
          <Route path="*" element={<Home />} />
        </Route>
      </Routes>
    </SessionGate>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <I18nProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </I18nProvider>
  </StrictMode>,
);
