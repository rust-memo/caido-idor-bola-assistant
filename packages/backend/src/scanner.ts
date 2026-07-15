import { createHash } from "crypto";

import type { SDK } from "caido:plugin";
import type { Request, RequestSpec, Response } from "caido:utils";

import { classifyOwnerControl, compareEvidence } from "./comparator";
import type { EvidenceResult, ResponseSample } from "./comparator";
import { analyzeMessage, parseRequestParameters } from "./detector";
import { ProfileManager } from "./profiles";
import { AssistantStore } from "./store";
import type {
  AnalyzerInput,
  AssistantSettings,
  CandidateRuleDTO,
  CaptureProfileInput,
  ComparisonInput,
  ComparisonResult,
  MessageDetails,
  PreparedMutation,
  ReviewStatus,
  ScanState,
  Snapshot,
} from "./types";

import type { BackendEvents } from "./index";

export type AssistantSDK = SDK<Record<string, never>, BackendEvents>;
type Work = {
  generation: number;
  projectId: string;
  request: Request;
  response: Response;
};
type ComparisonExecution = {
  result: ComparisonResult;
  authenticationFailure: boolean;
  crossStatus?: number;
};

const MESSAGE_PREVIEW_BYTES = 8 * 1024 * 1024;

export class IdorScanner {
  private readonly store = new AssistantStore();
  private readonly profiles = new ProfileManager();
  private settings?: AssistantSettings;
  private state: ScanState = {
    phase: "IDLE",
    queued: 0,
    active: 0,
    scanned: 0,
    dropped: 0,
    comparisonsSent: 0,
    message: "Idle",
  };
  private generation = 0;
  private historyReading = false;
  private paused = false;
  private monitorStarted = false;
  private monitorSince = new Date();
  private comparisonRunning = false;
  private comparisonCancelled = false;
  private draining = false;
  private readonly queue: Work[] = [];
  private readonly processed = new Set<string>();
  private activeWorkers = 0;

  async initialize(sdk: AssistantSDK): Promise<void> {
    await this.store.initialize(sdk);
    this.settings = await this.store.getSettings();
    sdk.events.onInterceptResponse((_eventSDK, request, response) => {
      void this.observe(sdk, request, response).catch((error) =>
        sdk.console.error(
          `IDOR Assistant response event failed: ${safeMessage(error)}`,
        ),
      );
    });
    sdk.events.onProjectChange((_eventSDK, project) => {
      this.monitorSince = new Date();
      this.profiles.clear();
      this.comparisonCancelled = true;
      this.cancel(
        sdk,
        project === null ? "No active project" : "Caido project changed",
      );
      const generation = this.generation;
      void this.finishProjectChange(sdk, project !== null, generation).catch(
        (error) =>
          sdk.console.error(
            `IDOR Assistant project rescan failed: ${safeMessage(error)}`,
          ),
      );
    });
    if (this.settings.autoHistory) await this.rescan(sdk, false);
    else this.resetRuntime(sdk, "Monitoring new responses");
    this.startMonitor(sdk);
  }

  async getSnapshot(sdk: AssistantSDK): Promise<Snapshot> {
    const projectId = await this.currentProjectId(sdk);
    const settings = this.requireSettings();
    if (projectId === undefined)
      return {
        candidates: [],
        observations: [],
        profiles: this.profiles.list(),
        rules: [],
        settings,
        state: { ...this.state, message: "No active Caido project" },
      };
    const candidates = await this.store.candidates(projectId);
    const observations = await this.store.observations(projectId);
    const rules = await this.store.rules(projectId);
    return {
      candidates,
      observations,
      profiles: this.profiles.list(),
      rules,
      settings,
      state: this.copyState(),
    };
  }

  async getMessage(
    sdk: AssistantSDK,
    requestId: string,
  ): Promise<MessageDetails | undefined> {
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined) return undefined;
    const requestPreview = rawPreview(
      pair.request.getRaw(),
      requestSummary(pair.request),
    );
    const responsePreview =
      pair.response === undefined
        ? { text: "", truncated: false }
        : rawPreview(pair.response.getRaw(), responseSummary(pair.response));
    return {
      requestId,
      request: requestPreview.text,
      response: responsePreview.text,
      requestTruncated: requestPreview.truncated,
      responseTruncated: responsePreview.truncated,
    };
  }

  async analyzeRequest(
    sdk: AssistantSDK,
    requestId: string,
  ): Promise<string | undefined> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(requestId);
    if (pair?.response === undefined)
      throw new Error("The selected request has no saved response");
    const settings = this.requireSettings();
    if (settings.scopeOnly && !sdk.requests.inScope(pair.request))
      throw new Error("The selected request is outside Caido Scope");
    const input = toAnalyzerInput(pair.request, pair.response, settings);
    const assessment = analyzeMessage(
      input,
      settings,
      await this.store.rules(projectId),
    );
    if (assessment === undefined) return undefined;
    await this.store.add(
      projectId,
      input,
      assessment,
      this.profiles.inferOwner(pair.request),
      settings.maxCandidates,
    );
    const snapshot = await this.getSnapshot(sdk);
    sdk.api.send("snapshot", snapshot);
    sdk.api.send("focus-candidate", assessment.fingerprint);
    return assessment.fingerprint;
  }

  async saveSettings(
    sdk: AssistantSDK,
    settings: AssistantSettings,
  ): Promise<AssistantSettings> {
    this.settings = await this.store.saveSettings(settings);
    this.monitorSince = new Date();
    await this.rescan(sdk, true);
    return this.settings;
  }

  async setStatus(
    sdk: AssistantSDK,
    fingerprint: string,
    status: ReviewStatus,
  ): Promise<void> {
    if (status === "CONFIRMED")
      throw new Error(
        "Use Confirm & publish after manually validating a suspicious comparison",
      );
    await this.store.setStatus(
      await this.requireProjectId(sdk),
      fingerprint,
      status,
    );
    this.emitSnapshot(sdk);
  }

  async captureProfile(
    sdk: AssistantSDK,
    input: CaptureProfileInput,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const pair = await sdk.requests.get(input.requestId);
    if (pair === undefined)
      throw new Error("The source request is unavailable");
    const profile = this.profiles.capture(pair.request, input.name, input.role);
    const observations = await this.store.observations(projectId);
    for (const observation of observations) {
      if (observation.requestId === input.requestId)
        await this.store.setObservationOwner(
          projectId,
          observation.id,
          profile.id,
        );
    }
    this.emitSnapshot(sdk);
  }

  async removeProfile(sdk: AssistantSDK, profileId: string): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    this.profiles.remove(profileId);
    await this.store.clearObservationOwnerProfile(projectId, profileId);
    this.emitSnapshot(sdk);
  }

  async assignOwner(
    sdk: AssistantSDK,
    observationId: string,
    profileId: string,
  ): Promise<void> {
    if (profileId !== "" && this.profiles.get(profileId) === undefined)
      throw new Error("Identity profile is no longer available");
    await this.store.setObservationOwner(
      await this.requireProjectId(sdk),
      observationId,
      profileId,
    );
    this.emitSnapshot(sdk);
  }

  async addRule(
    sdk: AssistantSDK,
    fingerprint: string,
    action: "IGNORE" | "ALLOW",
    scope: "HOST" | "ENDPOINT",
    reason: string,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(projectId, fingerprint);
    if (candidate === undefined) throw new Error("Candidate no longer exists");
    const reference = candidate.references.find(
      (value) =>
        value.source === "REQUEST" &&
        !["AUTH_CONTEXT", "PAGINATION", "TELEMETRY"].includes(value.role),
    );
    if (reference === undefined)
      throw new Error("No object reference is available");
    const rule: CandidateRuleDTO = {
      id: createHash("sha256")
        .update(
          `${fingerprint}:${action}:${scope}:${Date.now()}:${Math.random()}`,
        )
        .digest("hex")
        .slice(0, 24),
      action,
      scope,
      host: candidate.host,
      method: candidate.method,
      endpointTemplate: candidate.endpointTemplate,
      referenceName: reference.name,
      referenceLocation: reference.location,
      structuralPath: reference.structuralPath,
      reason: reason.trim() === "" ? "Reviewed local rule" : reason.trim(),
      createdAt: new Date().toISOString(),
    };
    await this.store.addRule(projectId, rule);
    await this.rescan(sdk, true);
  }

  async removeRule(sdk: AssistantSDK, id: string): Promise<void> {
    await this.store.removeRule(await this.requireProjectId(sdk), id);
    await this.rescan(sdk, true);
  }

  async runComparison(
    sdk: AssistantSDK,
    input: ComparisonInput,
  ): Promise<ComparisonResult> {
    if (this.comparisonRunning)
      throw new Error("A comparison is already running");
    this.comparisonRunning = true;
    this.comparisonCancelled = false;
    this.state.phase = "COMPARING";
    this.state.message = "Running explicit owner-versus-target comparison";
    this.publishState(sdk);
    const counter = { sent: 0 };
    try {
      const execution = await this.executeComparison(sdk, input, counter);
      return execution.result;
    } finally {
      this.comparisonRunning = false;
      this.finishComparison(sdk, counter.sent);
    }
  }

  async runBatch(
    sdk: AssistantSDK,
    inputs: ComparisonInput[],
  ): Promise<ComparisonResult[]> {
    if (this.comparisonRunning)
      throw new Error("A comparison is already running");
    if (inputs.length === 0) return [];
    this.comparisonRunning = true;
    this.comparisonCancelled = false;
    this.state.phase = "COMPARING";
    this.state.message = "Running bounded read-only comparison batch";
    this.publishState(sdk);
    const counter = { sent: 0 };
    const output: ComparisonResult[] = [];
    let authenticationFailures = 0;
    try {
      for (const input of inputs.slice(0, 100)) {
        if (this.comparisonCancelled) break;
        if (counter.sent + 2 > this.requireSettings().requestBudget) break;
        const execution = await this.executeComparison(sdk, input, counter);
        output.push(execution.result);
        if (execution.crossStatus === 429) break;
        authenticationFailures = execution.authenticationFailure
          ? authenticationFailures + 1
          : 0;
        if (authenticationFailures >= 3) break;
      }
      return output;
    } finally {
      this.comparisonRunning = false;
      this.finishComparison(sdk, counter.sent);
    }
  }

  cancelComparison(sdk: AssistantSDK): void {
    this.comparisonCancelled = true;
    this.state.message = "Comparison cancellation requested";
    this.publishState(sdk);
  }

  async prepareMutation(
    sdk: AssistantSDK,
    input: ComparisonInput,
  ): Promise<PreparedMutation> {
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(
      projectId,
      input.candidateFingerprint,
    );
    const observation = await this.store.getObservation(
      projectId,
      input.observationId,
    );
    if (candidate === undefined || observation === undefined)
      throw new Error("Candidate observation is no longer available");
    if (observation.candidateFingerprint !== candidate.fingerprint)
      throw new Error("Observation does not belong to this candidate");
    const pair = await sdk.requests.get(observation.requestId);
    if (pair === undefined) throw new Error("Source request is unavailable");
    if (["GET", "HEAD"].includes(pair.request.getMethod().toUpperCase()))
      throw new Error("Use controlled comparison for read-only requests");
    if (!sdk.requests.inScope(pair.request))
      throw new Error("Out-of-scope requests are blocked");
    const owner = this.profiles.get(input.ownerProfileId);
    if (owner === undefined)
      throw new Error("Owner identity profile is unavailable");
    const ownerSpec = this.profiles.apply(pair.request, owner);
    const crossSpec = this.crossSpec(pair.request, input);
    if (!sdk.requests.inScope(ownerSpec) || !sdk.requests.inScope(crossSpec))
      throw new Error("Out-of-scope requests are blocked");
    const original = await sdk.replay.createSession(ownerSpec);
    const cross = await sdk.replay.createSession(crossSpec);
    return {
      originalSessionId: original.getId(),
      crossSessionId: cross.getId(),
    };
  }

  async confirmAndPublish(
    sdk: AssistantSDK,
    fingerprint: string,
  ): Promise<void> {
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(projectId, fingerprint);
    if (candidate === undefined) throw new Error("Candidate no longer exists");
    if (candidate.comparisonStatus !== "Suspicious access")
      throw new Error(
        "Only manually reviewed suspicious comparisons can be confirmed",
      );
    const requestId = candidate.crossRequestId ?? candidate.requestId;
    const pair = await sdk.requests.get(requestId);
    if (pair === undefined)
      throw new Error("Comparison request is unavailable");
    await this.store.setStatus(projectId, fingerprint, "CONFIRMED");
    if (!candidate.published) {
      await sdk.findings.create({
        title: "Confirmed IDOR/BOLA access-control issue",
        description:
          `A manually confirmed owner-versus-other-identity comparison remained successful and preserved object-identity evidence.\n\n` +
          `Endpoint: ${candidate.method} ${candidate.host}${candidate.endpointTemplate}\n` +
          `Comparison: ${candidate.comparisonDetail}\n` +
          `Similarity: ${(candidate.similarity * 100).toFixed(1)}%\n` +
          `Owner baseline stability: ${(candidate.baselineStability * 100).toFixed(1)}%\n\n` +
          `The description omits authentication headers and raw object identifiers. Review the associated existing Caido request according to your project's data-handling rules.`,
        reporter: "IDOR BOLA Assistant",
        dedupeKey: fingerprint,
        request: pair.request,
      });
      await this.store.markPublished(projectId, fingerprint);
    }
    this.emitSnapshot(sdk);
  }

  async clear(sdk: AssistantSDK): Promise<void> {
    if (this.comparisonRunning)
      throw new Error("Stop the active comparison before clearing candidates");
    const projectId = await this.requireProjectId(sdk);
    this.cancel(sdk, "Unconfirmed candidates cleared");
    const generation = this.generation;
    this.draining = true;
    try {
      await this.waitForWorkers();
      if (generation !== this.generation) return;
      await this.store.clearUnconfirmed(projectId);
      this.state.scanned = 0;
      this.state.dropped = 0;
      this.state.message = "Unconfirmed candidates cleared";
    } finally {
      if (generation === this.generation) this.draining = false;
    }
    this.publishState(sdk);
    this.emitSnapshot(sdk);
  }

  async rescan(sdk: AssistantSDK, clear: boolean): Promise<void> {
    if (this.comparisonRunning)
      throw new Error("Stop the active comparison before rescanning History");
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) {
      this.cancel(sdk, "No active project");
      return;
    }
    this.generation += 1;
    const generation = this.generation;
    this.queue.length = 0;
    this.processed.clear();
    this.historyReading = true;
    this.draining = true;
    this.paused = false;
    this.state.scanned = 0;
    this.state.dropped = 0;
    this.state.phase = "SCANNING";
    this.state.message = "Reading Caido HTTP History";
    try {
      await this.waitForWorkers();
      if (generation !== this.generation) return;
      if (clear) await this.store.clearUnconfirmed(projectId);
    } finally {
      if (generation === this.generation) this.draining = false;
    }
    if (generation !== this.generation) return;
    this.publishState(sdk);
    this.emitSnapshot(sdk);
    void this.readHistory(sdk, projectId, generation);
  }

  pause(sdk: AssistantSDK): void {
    this.paused = true;
    if (!this.comparisonRunning) this.state.phase = "PAUSED";
    this.state.message = this.comparisonRunning
      ? "Passive analysis paused; comparison is still running"
      : "Passive analysis paused";
    this.publishState(sdk);
  }

  resume(sdk: AssistantSDK): void {
    this.paused = false;
    this.state.phase = this.comparisonRunning
      ? "COMPARING"
      : this.historyReading || this.queue.length > 0 || this.activeWorkers > 0
        ? "SCANNING"
        : "IDLE";
    this.state.message =
      this.state.phase === "IDLE"
        ? "Monitoring new responses"
        : "Passive analysis resumed";
    this.publishState(sdk);
    this.pump(sdk);
  }

  cancel(sdk: AssistantSDK, message = "Queued work cancelled"): void {
    this.generation += 1;
    this.queue.length = 0;
    this.historyReading = false;
    this.draining = false;
    this.paused = false;
    this.state.phase = this.comparisonRunning ? "COMPARING" : "IDLE";
    this.state.message = this.comparisonRunning
      ? `${message}; active comparison is finishing separately`
      : message;
    this.syncState();
    this.publishState(sdk);
  }

  private async executeComparison(
    sdk: AssistantSDK,
    input: ComparisonInput,
    counter: { sent: number },
  ): Promise<ComparisonExecution> {
    if (this.comparisonCancelled) throw new Error("Comparison cancelled");
    const projectId = await this.requireProjectId(sdk);
    const candidate = await this.store.getCandidate(
      projectId,
      input.candidateFingerprint,
    );
    const observation = await this.store.getObservation(
      projectId,
      input.observationId,
    );
    if (candidate === undefined || observation === undefined)
      throw new Error("Candidate observation is no longer available");
    if (observation.candidateFingerprint !== candidate.fingerprint)
      throw new Error("Observation does not belong to this candidate");
    const pair = await sdk.requests.get(observation.requestId);
    if (pair === undefined || pair.response === undefined)
      throw new Error("Original request and response are unavailable");
    if (!["GET", "HEAD"].includes(pair.request.getMethod().toUpperCase()))
      throw new Error(
        "Active comparison permits GET and HEAD only; use Replay for mutations",
      );
    if (!sdk.requests.inScope(pair.request))
      throw new Error("Out-of-scope requests are blocked");
    const owner = this.profiles.get(input.ownerProfileId);
    if (owner === undefined)
      throw new Error("Owner identity profile is unavailable");
    const ownerSpec = this.profiles.apply(pair.request, owner);
    const crossSpec = this.crossSpec(pair.request, input);
    if (!sdk.requests.inScope(ownerSpec) || !sdk.requests.inScope(crossSpec))
      throw new Error("Out-of-scope requests are blocked");

    const rules = await this.store.rules(projectId);
    const sourceInput = toAnalyzerInput(
      pair.request,
      pair.response,
      this.requireSettings(),
    );
    const assessment = analyzeMessage(
      sourceInput,
      this.requireSettings(),
      rules,
    );
    if (assessment === undefined)
      throw new Error("Candidate no longer passes detection");
    const ownerPair = await this.send(sdk, ownerSpec, counter);
    const ownerSample = responseSample(
      ownerPair.response,
      this.requireSettings().maxResponseBytes,
    );
    const ownerBarrier = classifyOwnerControl(ownerSample);
    if (ownerBarrier !== undefined) {
      const limited: ComparisonResult = {
        candidateFingerprint: candidate.fingerprint,
        status: "Inconclusive",
        detail: ownerBarrier.detail,
        confidence: "LOW",
        similarity: 0,
        baselineStability: 0,
        ownershipEvidence: false,
        indicators: [
          `owner control HTTP ${ownerPair.response.getCode()}`,
          "cross-identity request skipped",
        ],
        ownerControlRequestId: ownerPair.request.getId(),
      };
      await this.store.saveComparison(projectId, limited);
      this.emitSnapshot(sdk);
      return {
        result: limited,
        authenticationFailure: ownerBarrier.authenticationFailure,
      };
    }
    const crossPair = await this.send(sdk, crossSpec, counter);
    const evidence = compareEvidence(
      responseSample(pair.response, this.requireSettings().maxResponseBytes),
      ownerSample,
      responseSample(
        crossPair.response,
        this.requireSettings().maxResponseBytes,
      ),
      assessment.references,
      this.requireSettings().volatileFields,
    );
    const result = toComparisonResult(
      candidate.fingerprint,
      evidence,
      ownerPair.request.getId(),
      crossPair.request.getId(),
    );
    await this.store.saveComparison(projectId, result);
    this.emitSnapshot(sdk);
    return {
      result,
      authenticationFailure: evidence.authenticationFailure,
      crossStatus: crossPair.response.getCode(),
    };
  }

  private crossSpec(request: Request, input: ComparisonInput): RequestSpec {
    if (input.anonymous) return this.profiles.anonymous(request);
    if (input.targetProfileId === undefined)
      throw new Error("Target identity profile is required");
    const owner = this.profiles.get(input.ownerProfileId);
    const target = this.profiles.get(input.targetProfileId);
    if (target === undefined)
      throw new Error("Target identity profile is unavailable");
    if (owner !== undefined && owner.fingerprint === target.fingerprint)
      throw new Error(
        "Owner and target profiles have the same authentication fingerprint",
      );
    return this.profiles.apply(request, target);
  }

  private async send(
    sdk: AssistantSDK,
    spec: RequestSpec,
    counter: { sent: number },
  ) {
    if (this.comparisonCancelled) throw new Error("Comparison cancelled");
    if (counter.sent >= this.requireSettings().requestBudget)
      throw new Error(
        `Stopped at the ${this.requireSettings().requestBudget} request budget`,
      );
    if (counter.sent > 0 && this.requireSettings().delayMilliseconds > 0)
      await sleep(this.requireSettings().delayMilliseconds);
    if (this.comparisonCancelled) throw new Error("Comparison cancelled");
    counter.sent += 1;
    this.state.comparisonsSent += 1;
    this.publishState(sdk);
    return sdk.requests.send(spec);
  }

  private finishComparison(sdk: AssistantSDK, sent: number): void {
    this.state.phase = this.paused
      ? "PAUSED"
      : this.historyReading || this.queue.length > 0 || this.activeWorkers > 0
        ? "SCANNING"
        : "IDLE";
    this.state.message = `Comparison finished after ${sent} explicit request${sent === 1 ? "" : "s"}`;
    this.publishState(sdk);
    this.emitSnapshot(sdk);
  }

  private async readHistory(
    sdk: AssistantSDK,
    projectId: string,
    generation: number,
  ): Promise<void> {
    const settings = this.requireSettings();
    let cursor: string | undefined;
    let inspected = 0;
    try {
      while (
        inspected < settings.maxHistoryEntries &&
        generation === this.generation
      ) {
        const amount = Math.min(200, settings.maxHistoryEntries - inspected);
        let query = sdk.requests
          .query()
          .descending("req", "created_at")
          .first(amount);
        if (cursor !== undefined) query = query.after(cursor);
        const page = await query.execute();
        if (page.items.length === 0) break;
        for (const item of page.items) {
          if (generation !== this.generation) return;
          inspected += 1;
          if (item.response === undefined) continue;
          if (settings.scopeOnly && !sdk.requests.inScope(item.request))
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
          });
          while (this.queue.length > 100 && generation === this.generation)
            await sleep(20);
        }
        if (!page.pageInfo.hasNextPage) break;
        cursor = page.pageInfo.endCursor;
      }
      if (generation === this.generation)
        this.state.message = `Queued ${inspected} recent History entries`;
    } catch (error) {
      this.state.message = `History scan failed: ${safeMessage(error)}`;
      sdk.console.error(this.state.message);
    } finally {
      if (generation === this.generation) {
        this.historyReading = false;
        this.finishIfIdle(sdk);
      }
    }
  }

  private async observe(
    sdk: AssistantSDK,
    request: Request,
    response: Response,
  ): Promise<void> {
    const settings = this.requireSettings();
    if (settings.scopeOnly && !sdk.requests.inScope(request)) return;
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) return;
    this.enqueue(sdk, {
      generation: this.generation,
      projectId,
      request,
      response,
    });
  }

  private startMonitor(sdk: AssistantSDK): void {
    if (this.monitorStarted) return;
    this.monitorStarted = true;
    void this.monitorRecentHistory(sdk);
  }

  private async monitorRecentHistory(sdk: AssistantSDK): Promise<void> {
    while (this.monitorStarted) {
      await sleep(1_500);
      if (this.paused) continue;
      try {
        const projectId = await this.currentProjectId(sdk);
        if (projectId === undefined) continue;
        const generation = this.generation;
        const settings = this.requireSettings();
        const page = await sdk.requests
          .query()
          .descending("req", "created_at")
          .first(Math.min(200, settings.maxHistoryEntries))
          .execute();
        if (generation !== this.generation) continue;
        for (const item of page.items) {
          if (item.response === undefined) continue;
          const key = `${projectId}:${item.request.getId()}`;
          if (this.processed.has(key)) continue;
          if (
            !settings.autoHistory &&
            item.request.getCreatedAt() < this.monitorSince
          )
            continue;
          if (settings.scopeOnly && !sdk.requests.inScope(item.request))
            continue;
          this.enqueue(sdk, {
            generation,
            projectId,
            request: item.request,
            response: item.response,
          });
        }
      } catch (error) {
        sdk.console.error(
          `IDOR Assistant monitor failed: ${safeMessage(error)}`,
        );
      }
    }
  }

  private enqueue(sdk: AssistantSDK, work: Work): void {
    const key = `${work.projectId}:${work.request.getId()}`;
    if (
      this.draining ||
      work.generation !== this.generation ||
      this.processed.has(key)
    )
      return;
    this.processed.add(key);
    if (this.processed.size > this.requireSettings().maxHistoryEntries * 2) {
      const oldest = this.processed.values().next().value;
      if (oldest !== undefined) this.processed.delete(oldest);
    }
    if (this.queue.length >= 250) {
      this.processed.delete(key);
      this.state.dropped += 1;
      this.publishState(sdk);
      return;
    }
    this.queue.push(work);
    if (!this.comparisonRunning)
      this.state.phase = this.paused ? "PAUSED" : "SCANNING";
    this.syncState();
    this.publishState(sdk);
    this.pump(sdk);
  }

  private pump(sdk: AssistantSDK): void {
    if (this.paused || this.draining) return;
    while (this.activeWorkers < 2 && this.queue.length > 0) {
      const work = this.queue.shift();
      if (work === undefined) break;
      this.activeWorkers += 1;
      this.syncState();
      void this.process(sdk, work)
        .catch((error) =>
          sdk.console.error(
            `IDOR Assistant scan failed: ${safeMessage(error)}`,
          ),
        )
        .finally(() => {
          this.activeWorkers -= 1;
          this.syncState();
          this.publishState(sdk);
          this.emitSnapshot(sdk);
          this.pump(sdk);
          this.finishIfIdle(sdk);
        });
    }
  }

  private async process(sdk: AssistantSDK, work: Work): Promise<void> {
    if (work.generation !== this.generation) return;
    const input = toAnalyzerInput(
      work.request,
      work.response,
      this.requireSettings(),
    );
    const rules = await this.store.rules(work.projectId);
    if (work.generation !== this.generation) return;
    const assessment = analyzeMessage(input, this.requireSettings(), rules);
    if (assessment !== undefined) {
      if (work.generation !== this.generation) return;
      await this.store.add(
        work.projectId,
        input,
        assessment,
        this.profiles.inferOwner(work.request),
        this.requireSettings().maxCandidates,
      );
    }
    if (work.generation === this.generation) this.state.scanned += 1;
  }

  private finishIfIdle(sdk: AssistantSDK): void {
    if (
      this.comparisonRunning ||
      this.draining ||
      this.historyReading ||
      this.queue.length > 0 ||
      this.activeWorkers > 0
    )
      return;
    this.state.phase = this.paused ? "PAUSED" : "IDLE";
    this.state.message = `Passive analysis complete: ${this.state.scanned} responses analyzed`;
    this.syncState();
    this.publishState(sdk);
    this.emitSnapshot(sdk);
  }

  private resetRuntime(sdk: AssistantSDK, message: string): void {
    this.generation += 1;
    this.queue.length = 0;
    this.processed.clear();
    this.historyReading = false;
    this.paused = false;
    this.state.phase = "IDLE";
    this.state.message = message;
    this.state.scanned = 0;
    this.state.dropped = 0;
    this.draining = false;
    this.publishState(sdk);
  }

  private syncState(): void {
    this.state.queued = this.queue.length;
    this.state.active = this.activeWorkers;
  }

  private async waitForWorkers(): Promise<void> {
    while (this.activeWorkers > 0) await sleep(20);
  }

  private async finishProjectChange(
    sdk: AssistantSDK,
    hasProject: boolean,
    generation: number,
  ): Promise<void> {
    while (this.comparisonRunning) await sleep(20);
    if (generation !== this.generation || !hasProject) return;
    if (this.requireSettings().autoHistory) await this.rescan(sdk, false);
    else this.resetRuntime(sdk, "Monitoring new responses");
  }

  private publishState(sdk: AssistantSDK): void {
    this.syncState();
    sdk.api.send("scan-state", this.copyState());
  }

  private copyState(): ScanState {
    return { ...this.state };
  }

  private emitSnapshot(sdk: AssistantSDK): void {
    void this.getSnapshot(sdk)
      .then((snapshot) => sdk.api.send("snapshot", snapshot))
      .catch((error) =>
        sdk.console.error(`Snapshot update failed: ${safeMessage(error)}`),
      );
  }

  private requireSettings(): AssistantSettings {
    if (this.settings === undefined)
      throw new Error("Settings are not initialized");
    return this.settings;
  }

  private async currentProjectId(
    sdk: AssistantSDK,
  ): Promise<string | undefined> {
    return (await sdk.projects.getCurrent())?.getId();
  }

  private async requireProjectId(sdk: AssistantSDK): Promise<string> {
    const projectId = await this.currentProjectId(sdk);
    if (projectId === undefined) throw new Error("No active Caido project");
    return projectId;
  }
}

function toAnalyzerInput(
  request: Request,
  response: Response,
  settings: AssistantSettings,
): AnalyzerInput {
  const requestBody = request.getBody();
  const requestRaw = requestBody?.toRaw();
  const body =
    requestRaw !== undefined && requestRaw.length <= settings.maxRequestBytes
      ? (requestBody?.toText() ?? "")
      : "";
  const responseBody = response.getBody();
  const responseRaw = responseBody?.toRaw();
  const responseText =
    responseRaw !== undefined &&
    responseRaw.length <= settings.maxResponseBytes &&
    isTextResponse(request, response)
      ? (responseBody?.toText() ?? "")
      : "";
  const contentType = (request.getHeader("Content-Type") ?? []).join(" ");
  return {
    requestId: request.getId(),
    responseId: response.getId(),
    method: request.getMethod(),
    url: request.getUrl(),
    host: request.getHost(),
    path: request.getPath(),
    query: request.getQuery(),
    headers: request.getHeaders(),
    parameters: parseRequestParameters(
      request.getQuery(),
      body,
      contentType,
      request.getHeader("Cookie") ?? [],
    ),
    body,
    contentType,
    responseStatus: response.getCode(),
    responseHeaders: response.getHeaders(),
    responseBody: responseText,
    responseContentType: (response.getHeader("Content-Type") ?? []).join(" "),
  };
}

function responseSample(response: Response, maximum: number): ResponseSample {
  const body = response.getBody();
  const raw = body?.toRaw();
  if (raw !== undefined && raw.length > maximum)
    throw new Error("Comparison response exceeds the configured body limit");
  return {
    status: response.getCode(),
    contentType: (response.getHeader("Content-Type") ?? []).join(" "),
    body: body?.toText() ?? "",
  };
}

function isTextResponse(request: Request, response: Response): boolean {
  const contentType = (response.getHeader("Content-Type") ?? [])
    .join(" ")
    .toLowerCase();
  const path = request.getPath().toLowerCase();
  return !(
    /(image|audio|video|font|octet-stream|pdf|zip)/.test(contentType) ||
    /\.(?:png|jpe?g|gif|webp|avif|ico|woff2?|ttf|pdf|zip|gz)$/.test(path)
  );
}

function toComparisonResult(
  fingerprint: string,
  evidence: EvidenceResult,
  ownerControlRequestId: string,
  crossRequestId: string,
): ComparisonResult {
  return {
    candidateFingerprint: fingerprint,
    status: evidence.status,
    detail: `${evidence.detail}; similarity ${(evidence.similarity * 100).toFixed(1)}%; baseline ${(evidence.baselineStability * 100).toFixed(1)}%`,
    confidence: evidence.confidence,
    similarity: evidence.similarity,
    baselineStability: evidence.baselineStability,
    ownershipEvidence: evidence.ownershipEvidence,
    indicators: evidence.indicators,
    ownerControlRequestId,
    crossRequestId,
  };
}

function rawPreview(
  raw: { toBytes: () => Uint8Array; toText: () => string },
  summary: string,
): { text: string; truncated: boolean } {
  if (raw.toBytes().length <= MESSAGE_PREVIEW_BYTES)
    return { text: raw.toText(), truncated: false };
  return {
    text: `${summary}\r\n\r\n[Preview omitted: message exceeds the 8 MiB editor limit. The complete message remains available in Caido HTTP History.]`,
    truncated: true,
  };
}

function requestSummary(request: Request): string {
  const query = request.getQuery();
  const target = `${request.getPath()}${query === "" ? "" : `?${query}`}`;
  return [
    `${request.getMethod()} ${target} HTTP/1.1`,
    ...headerLines(request.getHeaders()),
  ].join("\r\n");
}

function responseSummary(response: Response): string {
  return [
    `HTTP/1.1 ${response.getCode()}`,
    ...headerLines(response.getHeaders()),
  ].join("\r\n");
}

function headerLines(headers: Record<string, string[]>): string[] {
  return Object.entries(headers).flatMap(([name, values]) =>
    values.slice(0, 20).map((value) => `${name}: ${value}`),
  );
}

function sleep(milliseconds: number): Promise<void> {
  // eslint-disable-next-line compat/compat -- Promise is provided by Caido's QuickJS runtime.
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
