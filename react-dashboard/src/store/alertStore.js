import { create } from "zustand";

export const useAlertStore = create((set) => ({
  liveAlerts: [],
  addAlert: (alert) =>
    set((state) => ({
      liveAlerts: [alert, ...state.liveAlerts].slice(0, 50),
    })),
  clearAlerts: () => set({ liveAlerts: [] }),
}));
