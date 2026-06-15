import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { installTaskEventBridge } from "./store/taskEventBridge";
import "./styles/global.css";
import "./styles/ui.css";

// Install the cross-store bridge once at boot — keeps EventStore disposition
// chips in sync with TaskStore lifecycle without any per-component wiring.
installTaskEventBridge();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);

