import type { UpdateChannel } from "./types";

const storageKey = "artex_update_channel";
const changeEvent = "artex:update-channel";
let memoryChannel: UpdateChannel = "stable";
let useMemory = false;

export function isUpdateChannel(value: unknown): value is UpdateChannel {
  return value === "stable" || value === "nightly" || value === "main";
}

export function getUpdateChannel(): UpdateChannel {
  if (typeof window === "undefined") return "stable";
  if (useMemory) return memoryChannel;
  try {
    const value = window.localStorage.getItem(storageKey);
    return isUpdateChannel(value) ? value : "stable";
  } catch {
    return memoryChannel;
  }
}

export function getServerUpdateChannel(): UpdateChannel {
  return "stable";
}

export function setUpdateChannel(channel: UpdateChannel): void {
  if (!isUpdateChannel(channel) || typeof window === "undefined") return;
  memoryChannel = channel;
  try {
    window.localStorage.setItem(storageKey, channel);
    useMemory = false;
  } catch {
    // Keep the choice for this page when browser storage is unavailable.
    useMemory = true;
  }
  window.dispatchEvent(new Event(changeEvent));
}

export function subscribeUpdateChannel(onChange: () => void): () => void {
  const onStorage = (event: StorageEvent) => {
    if (event.key !== storageKey && event.key !== null) return;
    try {
      if (event.key === storageKey) {
        const value = window.localStorage.getItem(storageKey);
        if (isUpdateChannel(value)) {
          memoryChannel = value;
        }
      } else {
        memoryChannel = "stable";
      }
    } catch {
      // Keep the local fallback when storage reads fail.
    }
    onChange();
  };
  window.addEventListener(changeEvent, onChange);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(changeEvent, onChange);
    window.removeEventListener("storage", onStorage);
  };
}
