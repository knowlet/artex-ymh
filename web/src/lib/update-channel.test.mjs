import {
  getServerUpdateChannel,
  getUpdateChannel,
  isUpdateChannel,
  setUpdateChannel,
  subscribeUpdateChannel,
} from "./update-channel.ts";
import assert from "node:assert/strict";
import test from "node:test";

const store = new Map();
const events = new EventTarget();
globalThis.window = events;
window.localStorage = {
  getItem: (key) => store.get(key) ?? null,
  setItem: (key, value) => store.set(key, value),
};

test("defaults and corrupted storage cannot choose an arbitrary update source", () => {
  store.clear();
  assert.equal(getServerUpdateChannel(), "stable");
  assert.equal(getUpdateChannel(), "stable");
  for (const value of ["https://example.com", "MAIN", "__proto__", null]) {
    store.set("artex_update_channel", value);
    assert.equal(isUpdateChannel(value), false);
    assert.equal(getUpdateChannel(), "stable");
    setUpdateChannel(value);
    assert.equal(getUpdateChannel(), "stable");
  }
});

test("a channel choice is persisted and both subscribers observe it", () => {
  const snapshots = [[], []];
  const unsubscribe = snapshots.map((values) => subscribeUpdateChannel(() => values.push(getUpdateChannel())));
  setUpdateChannel("main");
  setUpdateChannel("nightly");
  assert.equal(store.get("artex_update_channel"), "nightly");
  assert.deepEqual(snapshots, [
    ["main", "nightly"],
    ["main", "nightly"],
  ]);
  unsubscribe.forEach((stop) => {
    stop();
  });
  setUpdateChannel("stable");
  assert.deepEqual(snapshots, [
    ["main", "nightly"],
    ["main", "nightly"],
  ]);
});

test("other tabs and storage clearing notify subscribers; unrelated keys do not", () => {
  const snapshots = [];
  const stop = subscribeUpdateChannel(() => snapshots.push(getUpdateChannel()));
  function storageEvent(key) {
    const event = new Event("storage");
    Object.defineProperty(event, "key", { value: key });
    window.dispatchEvent(event);
  }
  store.set("artex_update_channel", "main");
  storageEvent("artex_update_channel");
  storageEvent("artex_token");
  store.clear();
  storageEvent(null);
  assert.deepEqual(snapshots, ["main", "stable"]);
  stop();
});

test("blocked writes keep the selection usable even when reads still work", () => {
  const original = window.localStorage.setItem;
  window.localStorage.setItem = () => {
    throw new Error("quota exceeded");
  };
  setUpdateChannel("main");
  assert.equal(getUpdateChannel(), "main");
  window.localStorage.setItem = original;
  setUpdateChannel("stable");
  assert.equal(getUpdateChannel(), "stable");
});

test("server rendering never accesses browser storage", () => {
  const original = globalThis.window;
  delete globalThis.window;
  assert.equal(getUpdateChannel(), "stable");
  assert.doesNotThrow(() => setUpdateChannel("main"));
  globalThis.window = original;
});
