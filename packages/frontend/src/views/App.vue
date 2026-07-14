<script setup lang="ts">
import type {
  AssistantSettings,
  CandidateDTO,
  CandidateRuleDTO,
  ComparisonInput,
  ComparisonResult,
  MessageDetails,
  ObservationDTO,
  ProfileDTO,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "backend";
import {
  computed,
  nextTick,
  onMounted,
  onUnmounted,
  onUpdated,
  reactive,
  ref,
} from "vue";

import { useSDK } from "@/plugins/sdk";

type Tab = "candidates" | "profiles" | "testing" | "rules" | "settings";
type MessageKind = "source" | "owner" | "cross";

const sdk = useSDK();
const snapshot = ref<Snapshot>();
const activeTab = ref<Tab>("candidates");
const scanState = ref<ScanState>({
  phase: "IDLE",
  queued: 0,
  active: 0,
  scanned: 0,
  dropped: 0,
  comparisonsSent: 0,
  message: "Loading IDOR/BOLA Assistant",
});
const loading = ref(false);
const busy = ref(false);
const error = ref("");
const notice = ref("");
const search = ref("");
const dispositionFilter = ref("ACTIVE");
const priorityFilter = ref("ALL");
const reviewFilter = ref("ALL");
const comparisonFilter = ref("ALL");
const focusedFingerprint = ref("");
const selectedFingerprints = ref<string[]>([]);
const selectedObservationId = ref("");
const ownerProfileId = ref("");
const targetProfileId = ref("");
const anonymousTarget = ref(false);
const comparisonResult = ref<ComparisonResult>();
const message = ref<MessageDetails>();
const messageKind = ref<MessageKind>("source");
const requestHost = ref<HTMLElement>();
const responseHost = ref<HTMLElement>();
const requestEditor = sdk.ui.httpRequestEditor();
const responseEditor = sdk.ui.httpResponseEditor();
const profileName = ref("");
const profileRole = ref("");
const captureRequestId = ref("");
const ruleScope = ref<"HOST" | "ENDPOINT">("ENDPOINT");
const ruleReason = ref("");
const settings = reactive<AssistantSettings>({
  scopeOnly: true,
  autoHistory: true,
  maxRequestBytes: 1024 * 1024,
  maxResponseBytes: 2 * 1024 * 1024,
  maxHistoryEntries: 5_000,
  maxCandidates: 2_000,
  requestBudget: 20,
  delayMilliseconds: 250,
  customAllowNames: [],
  customDenyNames: [],
  ignoredPathFragments: [],
  volatileFields: [],
});
const allowNamesText = ref("");
const denyNamesText = ref("");
const ignoredPathsText = ref("");
const volatileFieldsText = ref("");

const maxRequestMb = computed({
  get: () => bytesToMb(settings.maxRequestBytes),
  set: (value: number) => {
    settings.maxRequestBytes = mbToBytes(value);
  },
});
const maxResponseMb = computed({
  get: () => bytesToMb(settings.maxResponseBytes),
  set: (value: number) => {
    settings.maxResponseBytes = mbToBytes(value);
  },
});

let snapshotListener: { stop: () => void } | undefined;
let stateListener: { stop: () => void } | undefined;

const candidates = computed(() => snapshot.value?.candidates ?? []);
const observations = computed(() => snapshot.value?.observations ?? []);
const profiles = computed(() => snapshot.value?.profiles ?? []);
const rules = computed(() => snapshot.value?.rules ?? []);
const activeCandidates = computed(
  () =>
    candidates.value.filter((candidate) => candidate.disposition === "ACTIVE")
      .length,
);
const suppressedCandidates = computed(
  () =>
    candidates.value.filter(
      (candidate) => candidate.disposition === "SUPPRESSED",
    ).length,
);
const suspiciousCandidates = computed(
  () =>
    candidates.value.filter(
      (candidate) => candidate.comparisonStatus === "Suspicious access",
    ).length,
);
const focusedCandidate = computed(() =>
  candidates.value.find(
    (candidate) => candidate.fingerprint === focusedFingerprint.value,
  ),
);
const focusedObservations = computed(() =>
  observations.value.filter(
    (observation) =>
      observation.candidateFingerprint === focusedFingerprint.value,
  ),
);
const selectedObservation = computed(() =>
  focusedObservations.value.find(
    (observation) => observation.id === selectedObservationId.value,
  ),
);
const ownerProfile = computed(() => profileById(ownerProfileId.value));
const targetProfile = computed(() => profileById(targetProfileId.value));
const filteredCandidates = computed(() =>
  candidates.value.filter((candidate) => {
    const query = search.value.trim().toLowerCase();
    const haystack =
      `${candidate.host} ${candidate.method} ${candidate.endpointTemplate} ${candidate.url} ${candidate.reasons.join(" ")} ${candidate.references.map((reference) => `${reference.name} ${reference.location}`).join(" ")}`.toLowerCase();
    return (
      (dispositionFilter.value === "ALL" ||
        candidate.disposition === dispositionFilter.value) &&
      (priorityFilter.value === "ALL" ||
        candidate.priority === priorityFilter.value) &&
      (reviewFilter.value === "ALL" ||
        candidate.reviewStatus === reviewFilter.value) &&
      (comparisonFilter.value === "ALL" ||
        comparisonGroup(candidate) === comparisonFilter.value) &&
      (query.length === 0 || haystack.includes(query))
    );
  }),
);
const matrixCandidates = computed(() =>
  selectedFingerprints.value.flatMap((fingerprint) => {
    const candidate = candidates.value.find(
      (value) => value.fingerprint === fingerprint,
    );
    return candidate === undefined ? [] : [candidate];
  }),
);
const comparisonReady = computed(() => {
  const candidate = focusedCandidate.value;
  if (
    candidate === undefined ||
    selectedObservation.value === undefined ||
    ownerProfile.value === undefined
  )
    return false;
  if (!anonymousTarget.value && targetProfile.value === undefined) return false;
  if (
    !anonymousTarget.value &&
    ownerProfile.value.fingerprint === targetProfile.value?.fingerprint
  )
    return false;
  return true;
});
const comparisonInput = computed<ComparisonInput | undefined>(() => {
  if (!comparisonReady.value) return undefined;
  return {
    candidateFingerprint: focusedCandidate.value?.fingerprint ?? "",
    observationId: selectedObservation.value?.id ?? "",
    ownerProfileId: ownerProfileId.value,
    targetProfileId: anonymousTarget.value ? undefined : targetProfileId.value,
    anonymous: anonymousTarget.value,
  };
});
const batchInputs = computed(() => {
  if (ownerProfile.value === undefined) return [];
  return selectedFingerprints.value.flatMap((fingerprint) => {
    const candidate = candidates.value.find(
      (value) => value.fingerprint === fingerprint,
    );
    if (
      candidate === undefined ||
      !["GET", "HEAD"].includes(candidate.method.toUpperCase())
    )
      return [];
    const observation = observations.value.find(
      (value) =>
        value.candidateFingerprint === fingerprint &&
        value.ownerProfileId === ownerProfileId.value,
    );
    if (observation === undefined) return [];
    return [
      {
        candidateFingerprint: fingerprint,
        observationId: observation.id,
        ownerProfileId: ownerProfileId.value,
        targetProfileId: anonymousTarget.value
          ? undefined
          : targetProfileId.value || undefined,
        anonymous: anonymousTarget.value,
      },
    ];
  });
});

onMounted(async () => {
  mountEditors();
  snapshotListener = sdk.backend.onEvent("snapshot", (value) => {
    snapshot.value = value;
    scanState.value = value.state;
    normalizeSelections();
  });
  stateListener = sdk.backend.onEvent("scan-state", (value) => {
    scanState.value = value;
  });
  await refresh();
});

onUpdated(mountEditors);

onUnmounted(() => {
  snapshotListener?.stop();
  stateListener?.stop();
});

function mountEditors() {
  if (
    requestHost.value !== undefined &&
    !requestHost.value.contains(requestEditor.getElement())
  )
    requestHost.value.append(requestEditor.getElement());
  if (
    responseHost.value !== undefined &&
    !responseHost.value.contains(responseEditor.getElement())
  )
    responseHost.value.append(responseEditor.getElement());
}

async function refresh(updateSettings = true) {
  if (loading.value) return;
  loading.value = true;
  try {
    const current = await sdk.backend.getSnapshot();
    snapshot.value = current;
    scanState.value = current.state;
    if (updateSettings) hydrateSettings(current.settings);
    normalizeSelections();
    error.value = "";
  } catch (cause) {
    error.value = safeMessage(cause);
  } finally {
    loading.value = false;
  }
}

function hydrateSettings(value: AssistantSettings) {
  Object.assign(settings, value);
  allowNamesText.value = value.customAllowNames.join("\n");
  denyNamesText.value = value.customDenyNames.join("\n");
  ignoredPathsText.value = value.ignoredPathFragments.join("\n");
  volatileFieldsText.value = value.volatileFields.join("\n");
}

function normalizeSelections() {
  selectedFingerprints.value = selectedFingerprints.value.filter(
    (fingerprint) =>
      candidates.value.some(
        (candidate) => candidate.fingerprint === fingerprint,
      ),
  );
  if (
    focusedFingerprint.value !== "" &&
    !candidates.value.some(
      (candidate) => candidate.fingerprint === focusedFingerprint.value,
    )
  ) {
    focusedFingerprint.value = "";
    selectedObservationId.value = "";
    message.value = undefined;
  }
  if (
    ownerProfileId.value !== "" &&
    profileById(ownerProfileId.value) === undefined
  )
    ownerProfileId.value = "";
  if (
    targetProfileId.value !== "" &&
    profileById(targetProfileId.value) === undefined
  )
    targetProfileId.value = "";
}

async function focusCandidate(candidate: CandidateDTO) {
  focusedFingerprint.value = candidate.fingerprint;
  const candidateObservations = observations.value.filter(
    (observation) => observation.candidateFingerprint === candidate.fingerprint,
  );
  const preferred =
    candidateObservations.find(
      (observation) => observation.ownerProfileId === ownerProfileId.value,
    ) ?? candidateObservations[0];
  selectedObservationId.value = preferred?.id ?? "";
  captureRequestId.value = preferred?.requestId ?? candidate.requestId;
  if (preferred?.ownerProfileId !== undefined)
    ownerProfileId.value = preferred.ownerProfileId;
  comparisonResult.value = undefined;
  await showMessage(candidate.requestId, "source");
}

async function chooseObservation(observation: ObservationDTO) {
  selectedObservationId.value = observation.id;
  captureRequestId.value = observation.requestId;
  if (observation.ownerProfileId !== undefined)
    ownerProfileId.value = observation.ownerProfileId;
  await showMessage(observation.requestId, "source");
}

async function showMessage(requestId: string | undefined, kind: MessageKind) {
  if (requestId === undefined || requestId === "") return;
  try {
    messageKind.value = kind;
    message.value = await sdk.backend.getMessage(requestId);
    setEditor(
      requestEditor,
      message.value?.request ?? "Request is no longer available in Caido.",
    );
    setEditor(
      responseEditor,
      message.value?.response ?? "Response is no longer available in Caido.",
    );
    error.value = "";
  } catch (cause) {
    error.value = safeMessage(cause);
  }
}

function setEditor(
  editor: ReturnType<typeof sdk.ui.httpRequestEditor>,
  text: string,
) {
  const view = editor.getEditorView();
  view.dispatch({
    changes: { from: 0, to: view.state.doc.length, insert: text },
  });
}

async function updateStatus(status: ReviewStatus) {
  const candidate = focusedCandidate.value;
  if (candidate === undefined) return;
  await perform(async () => {
    await sdk.backend.setStatus(candidate.fingerprint, status);
    await refresh(false);
    notice.value = `Review status changed to ${status}.`;
  });
}

async function captureProfile() {
  if (captureRequestId.value.trim() === "" || profileName.value.trim() === "") {
    error.value = "A request ID and profile name are required.";
    return;
  }
  await perform(async () => {
    await sdk.backend.captureProfile({
      requestId: captureRequestId.value.trim(),
      name: profileName.value,
      role: profileRole.value,
    });
    profileName.value = "";
    profileRole.value = "";
    notice.value =
      "Identity captured in memory. Authentication values are never shown in the UI.";
    await refresh(false);
  });
}

async function removeProfile(profile: ProfileDTO) {
  if (
    !window.confirm(
      `Remove identity profile '${profile.name}' and clear its observation assignments?`,
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.removeProfile(profile.id);
    await refresh(false);
  });
}

async function assignObservationOwner(
  observation: ObservationDTO,
  event: Event,
) {
  const value = (event.target as HTMLSelectElement).value;
  await perform(async () => {
    await sdk.backend.assignOwner(observation.id, value);
    if (value !== "") ownerProfileId.value = value;
    await refresh(false);
  });
}

async function runSingleComparison() {
  const input = comparisonInput.value;
  const candidate = focusedCandidate.value;
  if (input === undefined || candidate === undefined) {
    error.value =
      "Select a candidate observation, its owner, and a distinct target identity.";
    return;
  }
  if (!["GET", "HEAD"].includes(candidate.method.toUpperCase())) {
    error.value =
      "State-changing requests are never sent here. Prepare a manual Replay comparison instead.";
    return;
  }
  const target = anonymousTarget.value
    ? "an anonymous session"
    : `profile '${targetProfile.value?.name ?? "target"}'`;
  if (
    !window.confirm(
      `Send two in-scope ${candidate.method} requests: one owner control and one using ${target}? Only use this against an authorized target.`,
    )
  )
    return;
  await perform(async () => {
    comparisonResult.value = await sdk.backend.runComparison(input);
    notice.value = `Comparison completed: ${comparisonResult.value.status}.`;
    await refresh(false);
  });
}

async function runSelectedBatch() {
  if (!anonymousTarget.value && targetProfile.value === undefined) {
    error.value = "Choose a target identity or Anonymous.";
    return;
  }
  if (
    !anonymousTarget.value &&
    ownerProfile.value?.fingerprint === targetProfile.value?.fingerprint
  ) {
    error.value =
      "Owner and target profiles must have distinct authentication fingerprints.";
    return;
  }
  if (batchInputs.value.length === 0) {
    error.value =
      "No eligible selection. Batch requires GET/HEAD candidates with an observation assigned to the chosen owner.";
    return;
  }
  const maximumRequests = Math.min(
    settings.requestBudget,
    batchInputs.value.length * 2,
  );
  if (
    !window.confirm(
      `Run ${batchInputs.value.length} sequential owner-versus-target comparisons? This can send up to ${maximumRequests} in-scope requests with a ${settings.delayMilliseconds} ms delay.`,
    )
  )
    return;
  await perform(async () => {
    const results = await sdk.backend.runBatch(batchInputs.value);
    const suspicious = results.filter(
      (result) => result.status === "Suspicious access",
    ).length;
    notice.value = `Batch finished: ${results.length} cases, ${suspicious} suspicious.`;
    await refresh(false);
  });
}

async function prepareMutation() {
  const input = comparisonInput.value;
  const candidate = focusedCandidate.value;
  if (input === undefined || candidate === undefined) return;
  if (["GET", "HEAD"].includes(candidate.method.toUpperCase())) {
    error.value = "Use Compare one for read-only requests.";
    return;
  }
  if (
    !window.confirm(
      `Create owner and cross-identity Replay sessions for this ${candidate.method} request? Nothing will be sent automatically. Review mutation side effects before manually sending.`,
    )
  )
    return;
  await perform(async () => {
    const prepared = await sdk.backend.prepareMutation(input);
    const originalId = prepared.originalSessionId as Parameters<
      typeof sdk.replay.renameSession
    >[0];
    const crossId = prepared.crossSessionId as Parameters<
      typeof sdk.replay.renameSession
    >[0];
    await sdk.replay.renameSession(
      originalId,
      `IDOR owner - ${candidate.host}`,
    );
    await sdk.replay.renameSession(crossId, `IDOR cross - ${candidate.host}`);
    sdk.replay.openTab(crossId);
    notice.value =
      "Replay sessions created without sending. Compare and send them manually only after reviewing side effects.";
  });
}

async function publishConfirmed() {
  const candidate = focusedCandidate.value;
  if (candidate === undefined) return;
  if (
    !window.confirm(
      "Publish a redacted Caido Finding and mark this candidate CONFIRMED? Do this only after manually validating ownership and impact.",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.confirmAndPublish(candidate.fingerprint);
    notice.value = "Confirmed candidate published as a redacted Caido Finding.";
    await refresh(false);
  });
}

async function addRule(action: "IGNORE" | "ALLOW") {
  const candidate = focusedCandidate.value;
  if (candidate === undefined) return;
  const label =
    action === "IGNORE"
      ? "suppress matching candidates"
      : "allow matching evidence";
  if (
    !window.confirm(
      `Create a ${ruleScope.value.toLowerCase()} rule to ${label}? Unconfirmed candidates will be rebuilt from History.`,
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.addRule(
      candidate.fingerprint,
      action,
      ruleScope.value,
      ruleReason.value,
    );
    focusedFingerprint.value = "";
    selectedObservationId.value = "";
    notice.value = `${action} rule added; passive rescan started.`;
    await refresh(false);
  });
}

async function removeRule(rule: CandidateRuleDTO) {
  if (
    !window.confirm(
      `Remove this ${rule.scope.toLowerCase()} ${rule.action.toLowerCase()} rule and rescan History?`,
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.removeRule(rule.id);
    notice.value = "Rule removed; passive rescan started.";
    await refresh(false);
  });
}

async function applySettings() {
  await perform(async () => {
    settings.customAllowNames = splitList(allowNamesText.value);
    settings.customDenyNames = splitList(denyNamesText.value);
    settings.ignoredPathFragments = splitList(ignoredPathsText.value);
    settings.volatileFields = splitList(volatileFieldsText.value);
    const saved = await sdk.backend.saveSettings({ ...settings });
    hydrateSettings(saved);
    focusedFingerprint.value = "";
    notice.value =
      "Settings saved; unconfirmed candidates are being rescanned.";
    await refresh(false);
  });
}

async function rescan() {
  await perform(async () => {
    await sdk.backend.rescanHistory();
    notice.value = "Passive History rescan started.";
    await refresh(false);
  });
}

async function clearCandidates() {
  if (
    !window.confirm(
      "Clear all unconfirmed candidates and observations? Confirmed candidates remain.",
    )
  )
    return;
  await perform(async () => {
    await sdk.backend.clearCandidates();
    focusedFingerprint.value = "";
    selectedObservationId.value = "";
    selectedFingerprints.value = [];
    message.value = undefined;
    await refresh(false);
  });
}

async function togglePause() {
  await perform(async () => {
    if (scanState.value.phase === "PAUSED") await sdk.backend.resume();
    else await sdk.backend.pause();
  }, false);
}

async function cancelQueued() {
  await perform(async () => sdk.backend.cancel(), false);
}

async function cancelComparison() {
  await perform(async () => sdk.backend.cancelComparison(), false);
}

async function perform(action: () => Promise<unknown>, lock = true) {
  if (busy.value && lock) return;
  if (lock) busy.value = true;
  error.value = "";
  try {
    await action();
  } catch (cause) {
    error.value = safeMessage(cause);
  } finally {
    if (lock) busy.value = false;
  }
}

function toggleVisibleSelection() {
  const visible = filteredCandidates.value
    .filter((candidate) =>
      ["GET", "HEAD"].includes(candidate.method.toUpperCase()),
    )
    .map((candidate) => candidate.fingerprint);
  const allSelected = visible.every((fingerprint) =>
    selectedFingerprints.value.includes(fingerprint),
  );
  selectedFingerprints.value = allSelected
    ? selectedFingerprints.value.filter(
        (fingerprint) => !visible.includes(fingerprint),
      )
    : [...new Set([...selectedFingerprints.value, ...visible])];
}

function removeSelection(fingerprint: string) {
  selectedFingerprints.value = selectedFingerprints.value.filter(
    (value) => value !== fingerprint,
  );
}

function exportCandidates(format: "json" | "csv") {
  const values = filteredCandidates.value.map(exportableCandidate);
  const content =
    format === "json" ? JSON.stringify(values, undefined, 2) : toCSV(values);
  const blob = new Blob([content], {
    type: format === "json" ? "application/json" : "text/csv",
  });
  // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `caido-idor-bola-candidates.${format}`;
  anchor.click();
  // eslint-disable-next-line compat/compat -- Caido desktop webview supports object URLs.
  URL.revokeObjectURL(url);
}

function exportableCandidate(candidate: CandidateDTO) {
  return {
    priority: candidate.priority,
    score: candidate.score,
    disposition: candidate.disposition,
    reviewStatus: candidate.reviewStatus,
    comparisonStatus: candidate.comparisonStatus,
    comparisonConfidence: candidate.comparisonConfidence,
    method: candidate.method,
    host: candidate.host,
    endpointTemplate: candidate.endpointTemplate,
    responseStatus: candidate.responseStatus,
    references: candidate.references.map((reference) => ({
      name: reference.name,
      location: reference.location,
      structuralPath: reference.structuralPath,
      source: reference.source,
      role: reference.role,
      shape: reference.shape,
      sensitivity: reference.sensitivity,
      maskedValue: reference.maskedValue,
    })),
    reasons: candidate.reasons,
    occurrences: candidate.occurrenceCount,
    firstSeen: candidate.firstSeen,
    lastSeen: candidate.lastSeen,
    published: candidate.published,
  };
}

function toCSV(values: ReturnType<typeof exportableCandidate>[]): string {
  const columns: Array<keyof ReturnType<typeof exportableCandidate>> = [
    "priority",
    "score",
    "disposition",
    "reviewStatus",
    "comparisonStatus",
    "comparisonConfidence",
    "method",
    "host",
    "endpointTemplate",
    "responseStatus",
    "references",
    "reasons",
    "occurrences",
    "firstSeen",
    "lastSeen",
    "published",
  ];
  const escape = (value: unknown) => {
    let text =
      typeof value === "string"
        ? value
        : (JSON.stringify(value) ?? String(value));
    if (/^[=+@-]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  return `${columns.join(",")}\n${values.map((value) => columns.map((column) => escape(value[column])).join(",")).join("\n")}`;
}

function profileById(id: string): ProfileDTO | undefined {
  return profiles.value.find((profile) => profile.id === id);
}

function profileLabel(id: string | undefined): string {
  if (id === undefined) return "Unassigned";
  const profile = profileById(id);
  return profile === undefined
    ? "Unavailable profile"
    : `${profile.name}${profile.role === "" ? "" : ` · ${profile.role}`}`;
}

function comparisonGroup(candidate: CandidateDTO): string {
  if (candidate.comparisonStatus === "Suspicious access") return "SUSPICIOUS";
  if (candidate.comparisonStatus === "Likely protected") return "PROTECTED";
  if (candidate.comparisonStatus === "NOT_TESTED") return "NOT_TESTED";
  return "INCONCLUSIVE";
}

function resultClass(status: string): string {
  if (status === "Suspicious access") return "suspicious";
  if (status === "Likely protected") return "protected";
  return "inconclusive";
}

function splitList(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[,\r\n]+/)
        .map((entry) => entry.trim())
        .filter(Boolean),
    ),
  ];
}

function bytesToMb(value: number): number {
  return Math.max(0.02, Math.round((value / 1024 / 1024) * 100) / 100);
}

function mbToBytes(value: number): number {
  return Math.max(0.02, Number(value) || 0.02) * 1024 * 1024;
}

function formatDate(value: string): string {
  return value === "" ? "—" : new Date(value).toLocaleString();
}

function safeMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function activate(tab: Tab) {
  activeTab.value = tab;
  void nextTick(mountEditors);
}
</script>

<template>
  <main class="idor-shell">
    <header class="idor-header">
      <div>
        <div class="idor-title">IDOR / BOLA Assistant</div>
        <div class="idor-subtitle">
          Evidence-driven passive discovery · Explicit identity comparisons ·
          Observed object references only
        </div>
      </div>
      <div class="idor-metrics">
        <span :class="`phase-${scanState.phase}`">{{ scanState.phase }}</span>
        <span>Queued {{ scanState.queued }}</span>
        <span>Active {{ scanState.active }}</span>
        <span>Scanned {{ scanState.scanned }}</span>
        <span>Dropped {{ scanState.dropped }}</span>
        <span>Sent {{ scanState.comparisonsSent }}</span>
        <span>Active leads {{ activeCandidates }}</span>
        <span>Suspicious {{ suspiciousCandidates }}</span>
      </div>
    </header>

    <div class="idor-state-line">{{ scanState.message }}</div>
    <div v-if="error" class="idor-alert error">
      {{ error }}
      <button class="idor-link" @click="error = ''">dismiss</button>
    </div>
    <div v-if="notice" class="idor-alert notice">
      {{ notice }}
      <button class="idor-link" @click="notice = ''">dismiss</button>
    </div>

    <nav class="idor-tabs">
      <button
        class="idor-tab"
        :class="{ active: activeTab === 'candidates' }"
        @click="activate('candidates')"
      >
        Candidates ({{ activeCandidates }})
      </button>
      <button
        class="idor-tab"
        :class="{ active: activeTab === 'profiles' }"
        @click="activate('profiles')"
      >
        Identities ({{ profiles.length }})
      </button>
      <button
        class="idor-tab"
        :class="{ active: activeTab === 'testing' }"
        @click="activate('testing')"
      >
        Test matrix ({{ selectedFingerprints.length }})
      </button>
      <button
        class="idor-tab"
        :class="{ active: activeTab === 'rules' }"
        @click="activate('rules')"
      >
        Rules ({{ rules.length }})
      </button>
      <button
        class="idor-tab"
        :class="{ active: activeTab === 'settings' }"
        @click="activate('settings')"
      >
        Settings
      </button>
    </nav>

    <section v-if="activeTab === 'candidates'" class="idor-content">
      <div class="idor-toolbar">
        <button class="idor-button primary" :disabled="busy" @click="rescan">
          Rescan History
        </button>
        <button class="idor-button" @click="togglePause">
          {{ scanState.phase === "PAUSED" ? "Resume" : "Pause" }}
        </button>
        <button class="idor-button" @click="cancelQueued">Cancel queued</button>
        <button
          class="idor-button danger"
          :disabled="busy"
          @click="clearCandidates"
        >
          Clear unconfirmed
        </button>
        <input
          v-model="search"
          class="idor-input grow"
          placeholder="Search host, endpoint, reference, reason…"
        />
        <select v-model="dispositionFilter" class="idor-select">
          <option value="ACTIVE">Active</option>
          <option value="SUPPRESSED">
            Suppressed ({{ suppressedCandidates }})
          </option>
          <option value="ALL">All dispositions</option>
        </select>
        <select v-model="priorityFilter" class="idor-select">
          <option value="ALL">All priorities</option>
          <option>HIGH</option>
          <option>MEDIUM</option>
          <option>LOW</option>
        </select>
        <select v-model="reviewFilter" class="idor-select">
          <option value="ALL">All review states</option>
          <option>NEEDS_REVIEW</option>
          <option>REVIEWED</option>
          <option>FALSE_POSITIVE</option>
          <option>CONFIRMED</option>
        </select>
        <select v-model="comparisonFilter" class="idor-select">
          <option value="ALL">All comparison states</option>
          <option value="NOT_TESTED">Not tested</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="PROTECTED">Likely protected</option>
          <option value="INCONCLUSIVE">Inconclusive</option>
        </select>
        <button class="idor-button" @click="exportCandidates('json')">
          JSON
        </button>
        <button class="idor-button" @click="exportCandidates('csv')">
          CSV
        </button>
      </div>

      <div class="idor-toolbar actions">
        <button class="idor-button" @click="toggleVisibleSelection">
          Toggle visible GET/HEAD
        </button>
        <button
          class="idor-button"
          :disabled="!focusedCandidate"
          @click="updateStatus('REVIEWED')"
        >
          Reviewed
        </button>
        <button
          class="idor-button"
          :disabled="!focusedCandidate"
          @click="updateStatus('FALSE_POSITIVE')"
        >
          False positive
        </button>
        <button
          class="idor-button"
          :disabled="!focusedCandidate"
          @click="updateStatus('NEEDS_REVIEW')"
        >
          Reset review
        </button>
        <button
          class="idor-button accent"
          :disabled="
            !focusedCandidate ||
            focusedCandidate.comparisonStatus !== 'Suspicious access' ||
            focusedCandidate.published
          "
          @click="publishConfirmed"
        >
          {{
            focusedCandidate?.published
              ? "Finding published"
              : "Confirm & publish Finding"
          }}
        </button>
      </div>

      <div v-if="filteredCandidates.length" class="idor-table-wrap">
        <table class="idor-table candidates">
          <thead>
            <tr>
              <th class="check"><span class="sr-only">Batch</span></th>
              <th>Priority</th>
              <th>Score</th>
              <th>Review</th>
              <th>Comparison</th>
              <th>Method</th>
              <th>Endpoint</th>
              <th>Object reference</th>
              <th>Status</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="candidate in filteredCandidates"
              :key="candidate.fingerprint"
              :class="{
                selected: focusedFingerprint === candidate.fingerprint,
                suppressed: candidate.disposition === 'SUPPRESSED',
              }"
              @click="focusCandidate(candidate)"
            >
              <td class="check" @click.stop>
                <input
                  v-model="selectedFingerprints"
                  type="checkbox"
                  :value="candidate.fingerprint"
                  :disabled="
                    !['GET', 'HEAD'].includes(candidate.method.toUpperCase())
                  "
                  title="Add read-only candidate to Test matrix"
                />
              </td>
              <td>
                <span
                  class="idor-badge"
                  :class="`priority-${candidate.priority}`"
                >
                  {{ candidate.priority }}
                </span>
              </td>
              <td>{{ candidate.score }}</td>
              <td>{{ candidate.reviewStatus }}</td>
              <td>
                <span
                  class="idor-result-dot"
                  :class="resultClass(candidate.comparisonStatus)"
                />
                {{ candidate.comparisonStatus.replaceAll("_", " ") }}
              </td>
              <td>{{ candidate.method }}</td>
              <td :title="candidate.url">
                <strong>{{ candidate.host }}</strong
                >{{ candidate.endpointTemplate }}
              </td>
              <td>
                {{
                  candidate.references.find(
                    (reference) => reference.role === "OBJECT",
                  )?.name || "—"
                }}
              </td>
              <td>{{ candidate.responseStatus }}</td>
              <td>{{ candidate.occurrenceCount }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="idor-empty">
        No candidates match these filters. Suppressed low-evidence signals are
        hidden by default.
      </div>

      <section v-if="focusedCandidate" class="idor-detail">
        <div class="idor-detail-head">
          <div>
            <h2>
              {{ focusedCandidate.method }} {{ focusedCandidate.host
              }}{{ focusedCandidate.endpointTemplate }}
            </h2>
            <p>
              First {{ formatDate(focusedCandidate.firstSeen) }} · Last
              {{ formatDate(focusedCandidate.lastSeen) }} ·
              {{ focusedCandidate.occurrenceCount }} observations
            </p>
          </div>
          <span
            v-if="focusedCandidate.disposition === 'SUPPRESSED'"
            class="idor-badge suppressed"
          >
            {{ focusedCandidate.dispositionReason }}
          </span>
        </div>

        <div class="idor-detail-grid">
          <article class="idor-card">
            <h3>Detection reasons</h3>
            <ul>
              <li v-for="reason in focusedCandidate.reasons" :key="reason">
                {{ reason }}
              </li>
            </ul>
          </article>
          <article class="idor-card">
            <h3>Comparison evidence</h3>
            <p>
              <strong>{{ focusedCandidate.comparisonStatus }}</strong>
              <span v-if="focusedCandidate.comparisonConfidence">
                · {{ focusedCandidate.comparisonConfidence }} confidence
              </span>
            </p>
            <p>
              {{
                focusedCandidate.comparisonDetail ||
                "No controlled comparison has been run."
              }}
            </p>
            <div class="idor-progress-pair">
              <span
                >Similarity
                {{ Math.round(focusedCandidate.similarity * 100) }}%</span
              >
              <span
                >Baseline
                {{
                  Math.round(focusedCandidate.baselineStability * 100)
                }}%</span
              >
            </div>
          </article>
        </div>

        <div class="idor-table-wrap compact">
          <table class="idor-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Location</th>
                <th>Name / path</th>
                <th>Role</th>
                <th>Shape</th>
                <th>Sensitivity</th>
                <th>Masked value</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="reference in focusedCandidate.references"
                :key="`${reference.source}:${reference.location}:${reference.structuralPath}`"
              >
                <td>{{ reference.source }}</td>
                <td>{{ reference.location }}</td>
                <td>
                  {{ reference.name }}
                  <small>{{ reference.structuralPath }}</small>
                </td>
                <td>{{ reference.role }}</td>
                <td>{{ reference.shape }}</td>
                <td>{{ reference.sensitivity }}</td>
                <td>
                  <code>{{ reference.maskedValue }}</code>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="idor-toolbar evidence-tabs">
          <button
            class="idor-button"
            :class="{ active: messageKind === 'source' }"
            @click="
              showMessage(
                selectedObservation?.requestId || focusedCandidate.requestId,
                'source',
              )
            "
          >
            Source observation
          </button>
          <button
            class="idor-button"
            :class="{ active: messageKind === 'owner' }"
            :disabled="!focusedCandidate.ownerControlRequestId"
            @click="
              showMessage(focusedCandidate.ownerControlRequestId, 'owner')
            "
          >
            Owner control
          </button>
          <button
            class="idor-button"
            :class="{ active: messageKind === 'cross' }"
            :disabled="!focusedCandidate.crossRequestId"
            @click="showMessage(focusedCandidate.crossRequestId, 'cross')"
          >
            Cross identity
          </button>
        </div>
        <div class="idor-split">
          <div class="idor-editor">
            <div class="idor-editor-title">Request · {{ messageKind }}</div>
            <div ref="requestHost" class="idor-editor-host" />
          </div>
          <div class="idor-editor">
            <div class="idor-editor-title">Response · {{ messageKind }}</div>
            <div ref="responseHost" class="idor-editor-host" />
          </div>
        </div>
      </section>
    </section>

    <section v-else-if="activeTab === 'profiles'" class="idor-content">
      <div class="idor-warning">
        Profiles are held in memory only and are cleared when the Caido project
        changes or the plugin unloads. Authentication values are never returned
        to the frontend or included in exports.
      </div>
      <div class="idor-profile-capture">
        <label>
          <span>Caido request ID</span>
          <input
            v-model="captureRequestId"
            class="idor-input"
            placeholder="Select an observation or paste a Request ID"
          />
        </label>
        <label>
          <span>Identity name</span>
          <input v-model="profileName" class="idor-input" placeholder="Alice" />
        </label>
        <label>
          <span>Role / tenant</span>
          <input
            v-model="profileRole"
            class="idor-input"
            placeholder="user · tenant-a"
          />
        </label>
        <button
          class="idor-button primary"
          :disabled="busy"
          @click="captureProfile"
        >
          Capture identity
        </button>
      </div>

      <div v-if="profiles.length" class="idor-profile-grid">
        <article
          v-for="profile in profiles"
          :key="profile.id"
          class="idor-profile-card"
        >
          <div class="idor-profile-title">
            <div>
              <h2>{{ profile.name }}</h2>
              <p>{{ profile.role || "No role label" }}</p>
            </div>
            <button class="idor-button danger" @click="removeProfile(profile)">
              Remove
            </button>
          </div>
          <dl>
            <dt>Captured</dt>
            <dd>{{ formatDate(profile.capturedAt) }}</dd>
            <dt>Authentication headers</dt>
            <dd>{{ profile.headerNames.join(", ") }}</dd>
            <dt>Session substitutions</dt>
            <dd>{{ profile.substitutionNames.join(", ") || "none" }}</dd>
            <dt>Fingerprint</dt>
            <dd>
              <code>{{ profile.fingerprint.slice(0, 16) }}…</code>
            </dd>
          </dl>
        </article>
      </div>
      <div v-else class="idor-empty">
        No identities captured. Select a candidate observation, copy its Request
        ID here, then capture each dedicated test account.
      </div>
    </section>

    <section v-else-if="activeTab === 'testing'" class="idor-content">
      <div class="idor-warning strong">
        Controlled comparison is active testing. It sends only GET/HEAD
        requests, requires Caido Scope, never guesses identifiers, and uses only
        observed object references. Mutations are prepared in Replay without
        sending.
      </div>

      <div class="idor-matrix-controls">
        <label>
          <span>Owner identity</span>
          <select v-model="ownerProfileId" class="idor-select">
            <option value="">Choose owner…</option>
            <option
              v-for="profile in profiles"
              :key="profile.id"
              :value="profile.id"
            >
              {{ profile.name }}{{ profile.role ? ` · ${profile.role}` : "" }}
            </option>
          </select>
        </label>
        <label>
          <span>Target identity</span>
          <select
            v-model="targetProfileId"
            class="idor-select"
            :disabled="anonymousTarget"
          >
            <option value="">Choose target…</option>
            <option
              v-for="profile in profiles"
              :key="profile.id"
              :value="profile.id"
            >
              {{ profile.name }}{{ profile.role ? ` · ${profile.role}` : "" }}
            </option>
          </select>
        </label>
        <label class="idor-check">
          <input v-model="anonymousTarget" type="checkbox" />
          Compare as anonymous
        </label>
        <div class="idor-budget">
          Budget {{ settings.requestBudget }} requests · Delay
          {{ settings.delayMilliseconds }} ms
        </div>
        <button
          class="idor-button primary"
          :disabled="busy || batchInputs.length === 0"
          @click="runSelectedBatch"
        >
          Run eligible batch ({{ batchInputs.length }})
        </button>
        <button
          class="idor-button danger"
          :disabled="scanState.phase !== 'COMPARING'"
          @click="cancelComparison"
        >
          Stop comparison
        </button>
      </div>

      <div v-if="selectedFingerprints.length" class="idor-table-wrap">
        <table class="idor-table">
          <thead>
            <tr>
              <th>Candidate</th>
              <th>Method</th>
              <th>Owner observation</th>
              <th>Current result</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="candidate in matrixCandidates"
              :key="candidate.fingerprint"
              :class="{
                selected: focusedFingerprint === candidate.fingerprint,
              }"
              @click="focusCandidate(candidate)"
            >
              <td>{{ candidate.host }}{{ candidate.endpointTemplate }}</td>
              <td>{{ candidate.method }}</td>
              <td>
                {{
                  observations.some(
                    (observation) =>
                      observation.candidateFingerprint ===
                        candidate.fingerprint &&
                      observation.ownerProfileId === ownerProfileId,
                  )
                    ? profileLabel(ownerProfileId)
                    : "Assign an observation below"
                }}
              </td>
              <td>{{ candidate.comparisonStatus }}</td>
              <td class="right">
                <button
                  class="idor-link"
                  @click.stop="removeSelection(candidate.fingerprint)"
                >
                  remove
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="idor-empty">
        Select GET/HEAD rows in Candidates to build a bounded test matrix.
      </div>

      <section v-if="focusedCandidate" class="idor-test-case">
        <div class="idor-detail-head">
          <div>
            <h2>Focused case</h2>
            <p>
              {{ focusedCandidate.method }} {{ focusedCandidate.host
              }}{{ focusedCandidate.endpointTemplate }}
            </p>
          </div>
          <div class="idor-toolbar">
            <button
              v-if="
                ['GET', 'HEAD'].includes(focusedCandidate.method.toUpperCase())
              "
              class="idor-button primary"
              :disabled="busy || !comparisonReady"
              @click="runSingleComparison"
            >
              Compare one
            </button>
            <button
              v-else
              class="idor-button accent"
              :disabled="busy || !comparisonReady"
              @click="prepareMutation"
            >
              Prepare mutation in Replay
            </button>
          </div>
        </div>

        <div class="idor-table-wrap compact">
          <table class="idor-table">
            <thead>
              <tr>
                <th></th>
                <th>Observed</th>
                <th>Request ID</th>
                <th>Owner assignment</th>
                <th>Distinct references</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="observation in focusedObservations"
                :key="observation.id"
                :class="{ selected: selectedObservationId === observation.id }"
                @click="chooseObservation(observation)"
              >
                <td>
                  <input
                    type="radio"
                    :checked="selectedObservationId === observation.id"
                  />
                </td>
                <td>{{ formatDate(observation.observedAt) }}</td>
                <td>
                  <code>{{ observation.requestId }}</code>
                </td>
                <td @click.stop>
                  <select
                    class="idor-select"
                    :value="observation.ownerProfileId || ''"
                    @change="assignObservationOwner(observation, $event)"
                  >
                    <option value="">Unassigned</option>
                    <option
                      v-for="profile in profiles"
                      :key="profile.id"
                      :value="profile.id"
                    >
                      {{ profile.name
                      }}{{ profile.role ? ` · ${profile.role}` : "" }}
                    </option>
                  </select>
                </td>
                <td>{{ observation.referenceFingerprints.length }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <article
          v-if="comparisonResult"
          class="idor-result-card"
          :class="resultClass(comparisonResult.status)"
        >
          <h3>
            {{ comparisonResult.status }} ·
            {{ comparisonResult.confidence }} confidence
          </h3>
          <p>{{ comparisonResult.detail }}</p>
          <p>
            Object identity
            {{
              comparisonResult.ownershipEvidence
                ? "preserved"
                : "not established"
            }}
            · Similarity {{ Math.round(comparisonResult.similarity * 100) }}% ·
            Baseline {{ Math.round(comparisonResult.baselineStability * 100) }}%
          </p>
          <ul>
            <li
              v-for="indicator in comparisonResult.indicators"
              :key="indicator"
            >
              {{ indicator }}
            </li>
          </ul>
        </article>
      </section>
    </section>

    <section v-else-if="activeTab === 'rules'" class="idor-content">
      <div class="idor-warning">
        Rules contain selectors only—never raw object IDs, authentication
        values, or HTTP messages. Select a candidate first to add a narrow host
        or endpoint rule.
      </div>
      <div class="idor-toolbar">
        <select v-model="ruleScope" class="idor-select">
          <option value="ENDPOINT">Endpoint scope</option>
          <option value="HOST">Host scope</option>
        </select>
        <input
          v-model="ruleReason"
          class="idor-input grow"
          placeholder="Rule reason (recommended)"
        />
        <button
          class="idor-button danger"
          :disabled="!focusedCandidate || busy"
          @click="addRule('IGNORE')"
        >
          Ignore selected
        </button>
        <button
          class="idor-button primary"
          :disabled="!focusedCandidate || busy"
          @click="addRule('ALLOW')"
        >
          Allow selected
        </button>
      </div>
      <p v-if="focusedCandidate" class="idor-selected-rule-target">
        Target: {{ focusedCandidate.method }} {{ focusedCandidate.host
        }}{{ focusedCandidate.endpointTemplate }}
      </p>

      <div v-if="rules.length" class="idor-table-wrap">
        <table class="idor-table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Scope</th>
              <th>Selector</th>
              <th>Reference</th>
              <th>Reason</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="rule in rules" :key="rule.id">
              <td>
                <span class="idor-badge" :class="`rule-${rule.action}`">{{
                  rule.action
                }}</span>
              </td>
              <td>{{ rule.scope }}</td>
              <td>
                {{ rule.host }}
                <span v-if="rule.scope === 'ENDPOINT'"
                  >{{ rule.method }} {{ rule.endpointTemplate }}</span
                >
              </td>
              <td>{{ rule.referenceLocation }} · {{ rule.referenceName }}</td>
              <td>{{ rule.reason }}</td>
              <td>{{ formatDate(rule.createdAt) }}</td>
              <td>
                <button class="idor-link" @click="removeRule(rule)">
                  remove
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="idor-empty">No candidate rules.</div>
    </section>

    <section v-else class="idor-content settings">
      <div class="idor-warning">
        Scope-only mode is strongly recommended. Passive discovery sends no
        traffic. Saving settings rebuilds unconfirmed candidates from bounded
        History.
      </div>
      <div class="idor-settings-grid">
        <label class="idor-setting-row">
          <span>Analyze only requests in Caido Scope</span>
          <input v-model="settings.scopeOnly" type="checkbox" />
        </label>
        <label class="idor-setting-row">
          <span>Scan existing History automatically</span>
          <input v-model="settings.autoHistory" type="checkbox" />
        </label>
        <label class="idor-setting-row">
          <span>Maximum request body (MiB)</span>
          <input
            v-model.number="maxRequestMb"
            class="idor-input"
            type="number"
            min="0.02"
            max="10"
            step="0.1"
          />
        </label>
        <label class="idor-setting-row">
          <span>Maximum response body (MiB)</span>
          <input
            v-model.number="maxResponseMb"
            class="idor-input"
            type="number"
            min="0.02"
            max="20"
            step="0.1"
          />
        </label>
        <label class="idor-setting-row">
          <span>Maximum History entries</span>
          <input
            v-model.number="settings.maxHistoryEntries"
            class="idor-input"
            type="number"
            min="100"
            max="50000"
          />
        </label>
        <label class="idor-setting-row">
          <span>Maximum candidates</span>
          <input
            v-model.number="settings.maxCandidates"
            class="idor-input"
            type="number"
            min="100"
            max="20000"
          />
        </label>
        <label class="idor-setting-row">
          <span>Active request budget</span>
          <input
            v-model.number="settings.requestBudget"
            class="idor-input"
            type="number"
            min="2"
            max="100"
          />
        </label>
        <label class="idor-setting-row">
          <span>Delay between active requests (ms)</span>
          <input
            v-model.number="settings.delayMilliseconds"
            class="idor-input"
            type="number"
            min="0"
            max="5000"
          />
        </label>
        <label class="idor-setting-block">
          <span>Additional object-reference names</span>
          <textarea
            v-model="allowNamesText"
            class="idor-textarea"
            placeholder="cart_id\nshipment_id"
          />
        </label>
        <label class="idor-setting-block">
          <span>Reference names to deny</span>
          <textarea
            v-model="denyNamesText"
            class="idor-textarea"
            placeholder="tracking_id"
          />
        </label>
        <label class="idor-setting-block">
          <span>Ignored path fragments</span>
          <textarea
            v-model="ignoredPathsText"
            class="idor-textarea"
            placeholder="/assets/\n/health/"
          />
        </label>
        <label class="idor-setting-block">
          <span>Volatile response fields</span>
          <textarea
            v-model="volatileFieldsText"
            class="idor-textarea"
            placeholder="timestamp\nrequest_id"
          />
        </label>
      </div>
      <div class="idor-toolbar">
        <button
          class="idor-button primary"
          :disabled="busy"
          @click="applySettings"
        >
          Save and rescan
        </button>
      </div>
    </section>
  </main>
</template>
