import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { HomeRoute } from '@/routes/home';
import { LoginRoute } from '@/routes/login';

/** Hash routing, per the frontend manual: the SPA never has to guess what the server does with a path. */
export function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<HomeRoute />} />
        <Route path="/login" element={<LoginRoute />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </HashRouter>
  );
}
