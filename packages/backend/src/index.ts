import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";

import { IdorScanner } from "./scanner";
import type { AssistantSDK } from "./scanner";
import type {
  AssistantSettings,
  CaptureProfileInput,
  ComparisonInput,
  ComparisonResult,
  MessageDetails,
  PreparedMutation,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "./types";

const scanner = new IdorScanner();
const assistantSDK = (sdk: SDK): AssistantSDK => sdk;

const getSnapshot = (sdk: SDK): Promise<Snapshot> =>
  scanner.getSnapshot(assistantSDK(sdk));
const getMessage = (
  sdk: SDK,
  requestId: string,
): Promise<MessageDetails | undefined> =>
  scanner.getMessage(assistantSDK(sdk), requestId);
const analyzeRequest = (
  sdk: SDK,
  requestId: string,
): Promise<string | undefined> =>
  scanner.analyzeRequest(assistantSDK(sdk), requestId);
const saveSettings = (
  sdk: SDK,
  settings: AssistantSettings,
): Promise<AssistantSettings> =>
  scanner.saveSettings(assistantSDK(sdk), settings);
const setStatus = (
  sdk: SDK,
  fingerprint: string,
  status: ReviewStatus,
): Promise<void> => scanner.setStatus(assistantSDK(sdk), fingerprint, status);
const captureProfile = (sdk: SDK, input: CaptureProfileInput): Promise<void> =>
  scanner.captureProfile(assistantSDK(sdk), input);
const removeProfile = (sdk: SDK, profileId: string): Promise<void> =>
  scanner.removeProfile(assistantSDK(sdk), profileId);
const assignOwner = (
  sdk: SDK,
  observationId: string,
  profileId: string,
): Promise<void> =>
  scanner.assignOwner(assistantSDK(sdk), observationId, profileId);
const addRule = (
  sdk: SDK,
  fingerprint: string,
  action: "IGNORE" | "ALLOW",
  scope: "HOST" | "ENDPOINT",
  reason: string,
): Promise<void> =>
  scanner.addRule(assistantSDK(sdk), fingerprint, action, scope, reason);
const removeRule = (sdk: SDK, id: string): Promise<void> =>
  scanner.removeRule(assistantSDK(sdk), id);
const runComparison = (
  sdk: SDK,
  input: ComparisonInput,
): Promise<ComparisonResult> => scanner.runComparison(assistantSDK(sdk), input);
const runBatch = (
  sdk: SDK,
  inputs: ComparisonInput[],
): Promise<ComparisonResult[]> => scanner.runBatch(assistantSDK(sdk), inputs);
const cancelComparison = (sdk: SDK): void =>
  scanner.cancelComparison(assistantSDK(sdk));
const prepareMutation = (
  sdk: SDK,
  input: ComparisonInput,
): Promise<PreparedMutation> =>
  scanner.prepareMutation(assistantSDK(sdk), input);
const confirmAndPublish = (sdk: SDK, fingerprint: string): Promise<void> =>
  scanner.confirmAndPublish(assistantSDK(sdk), fingerprint);
const rescanHistory = (sdk: SDK): Promise<void> =>
  scanner.rescan(assistantSDK(sdk), true);
const clearCandidates = (sdk: SDK): Promise<void> =>
  scanner.clear(assistantSDK(sdk));
const pause = (sdk: SDK): void => scanner.pause(assistantSDK(sdk));
const resume = (sdk: SDK): void => scanner.resume(assistantSDK(sdk));
const cancel = (sdk: SDK): void => scanner.cancel(assistantSDK(sdk));

export type API = DefineAPI<{
  getSnapshot: typeof getSnapshot;
  getMessage: typeof getMessage;
  analyzeRequest: typeof analyzeRequest;
  saveSettings: typeof saveSettings;
  setStatus: typeof setStatus;
  captureProfile: typeof captureProfile;
  removeProfile: typeof removeProfile;
  assignOwner: typeof assignOwner;
  addRule: typeof addRule;
  removeRule: typeof removeRule;
  runComparison: typeof runComparison;
  runBatch: typeof runBatch;
  cancelComparison: typeof cancelComparison;
  prepareMutation: typeof prepareMutation;
  confirmAndPublish: typeof confirmAndPublish;
  rescanHistory: typeof rescanHistory;
  clearCandidates: typeof clearCandidates;
  pause: typeof pause;
  resume: typeof resume;
  cancel: typeof cancel;
}>;

export type BackendEvents = DefineEvents<{
  snapshot: (snapshot: Snapshot) => void;
  "scan-state": (state: ScanState) => void;
  "focus-candidate": (fingerprint: string) => void;
}>;

export function init(sdk: SDK<API, BackendEvents>) {
  sdk.api.register("getSnapshot", getSnapshot);
  sdk.api.register("getMessage", getMessage);
  sdk.api.register("analyzeRequest", analyzeRequest);
  sdk.api.register("saveSettings", saveSettings);
  sdk.api.register("setStatus", setStatus);
  sdk.api.register("captureProfile", captureProfile);
  sdk.api.register("removeProfile", removeProfile);
  sdk.api.register("assignOwner", assignOwner);
  sdk.api.register("addRule", addRule);
  sdk.api.register("removeRule", removeRule);
  sdk.api.register("runComparison", runComparison);
  sdk.api.register("runBatch", runBatch);
  sdk.api.register("cancelComparison", cancelComparison);
  sdk.api.register("prepareMutation", prepareMutation);
  sdk.api.register("confirmAndPublish", confirmAndPublish);
  sdk.api.register("rescanHistory", rescanHistory);
  sdk.api.register("clearCandidates", clearCandidates);
  sdk.api.register("pause", pause);
  sdk.api.register("resume", resume);
  sdk.api.register("cancel", cancel);
  void scanner
    .initialize(assistantSDK(sdk))
    .catch((error) =>
      sdk.console.error(
        `IDOR BOLA Assistant failed to initialize: ${String(error)}`,
      ),
    );
}

export type {
  AssistantSettings,
  CandidateDTO,
  CandidateRuleDTO,
  CaptureProfileInput,
  ComparisonInput,
  ComparisonResult,
  MessageDetails,
  ObservationDTO,
  PreparedMutation,
  ProfileDTO,
  ReferenceDTO,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "./types";
