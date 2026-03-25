# SWIFT Project System Directives

## Code Quality & Architecture
* **Strict Typing:** All Python code must use explicit type hints (PEP 484). All React code must be strictly structured and modular.
* **Error Handling:** Implement robust `try/except` blocks in the FastAPI backend. Never fail silently.
* **Performance:** Always optimize Pandas DataFrames for memory efficiency. Ensure React components do not cause unnecessary re-renders.

## UI/UX Standards (Frontend)
* **Design System:** Use Tailwind CSS exclusively. Do NOT write inline styles or custom CSS files.
* **Theme:** Enforce a strict, premium Dark Mode aesthetic (Slate/Zinc backgrounds). Use Neon Red (#ef4444) for malicious alerts and Emerald Green (#10b981) for benign logs.
* **Component Library:** Use `lucide-react` for all iconography. Use `recharts` for all data visualizations. Keep the interface clean, highly technical, and completely devoid of "toy" or generic web layouts.

## Operational Constraints
* Never execute offensive security tools or live network exploits.
* **Hardware Agnosticism:** Ensure all machine learning and data processing scripts are fully hardware-agnostic. Implement dynamic checks to utilize GPU acceleration if available, but always gracefully fall back to CPU execution so the application can run on any machine.