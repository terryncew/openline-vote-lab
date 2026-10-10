"use strict";

/* The interface renders returned evidence. It never invents a passing check. */
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { snapshot: null, stage: "vote", busy: false, polling: false };
  const stages = ["vote", "verify", "audit"];
  const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
  const working = (snapshot) => ["queued", "running"].includes(snapshot?.job?.status);
  const hasElection = () => Boolean(state.snapshot?.receipt && state.snapshot.cast_count === 100);

  async function request(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store"
    });
    let result;
    try { result = await response.json(); }
    catch { throw new Error("The demo returned an unreadable response. No result has been established."); }
    if (!response.ok) throw new Error(result.error || `The demo request failed (${response.status}).`);
    return result;
  }

  function activity(message, kind = "") {
    $("activity-text").textContent = message;
    $("activity").className = `activity ${kind}`;
  }

  function showError(message, retry = false) {
    $("connection-error-text").textContent = message;
    $("connection-error").hidden = false;
    $("retry-button").hidden = !retry;
  }

  function clearError() { $("connection-error").hidden = true; }

  function setStage(stage, focus = true) {
    if (!stages.includes(stage)) return;
    if (stage === "verify" && !hasElection()) return;
    if (stage === "audit" && !state.snapshot?.verification) return;
    state.stage = stage;
    for (const name of stages) $( `stage-${name}` ).hidden = name !== stage;
    renderControls();
    if (focus) {
      $(`${stage}-heading`).focus({ preventScroll: true });
      $("demo").scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    }
  }

  function renderControls() {
    const snapshot = state.snapshot;
    const busy = state.busy || working(snapshot);
    const ready = snapshot?.phase === "ready";
    const sealed = hasElection();
    const verified = Boolean(snapshot?.verification);
    const selected = document.querySelector("input[name=choice]:checked");
    $("choice-fieldset").disabled = busy || !ready;
    $("vote-button").disabled = busy || !ready || !selected;
    $("vote-button").firstChild.textContent = busy && snapshot?.job?.operation === "vote" ? "Encrypting the synthetic election " : sealed ? "Demo ballot already recorded " : "Encrypt my demo ballot ";
    $("verify-button").disabled = busy || !sealed;
    $("verify-button").firstChild.textContent = busy && snapshot?.job?.operation === "verify" ? "Checking the evidence " : verified ? "Check the evidence again " : "Check the evidence ";
    $("to-audit").disabled = busy || !verified;
    $("attack-delete").disabled = busy || !verified;
    $("attack-suppress").disabled = busy || !verified;
    $("restart-button").disabled = busy || !sealed;
    $("copy-receipt").disabled = !snapshot?.receipt?.payload?.ballot_hash;
    document.body.classList.toggle("working", busy);
    $("demo").setAttribute("aria-busy", String(busy));
    for (const button of document.querySelectorAll("[data-stage]")) {
      const name = button.dataset.stage;
      button.disabled = name === "verify" ? !sealed : name === "audit" ? !verified : false;
      button.classList.toggle("active", name === state.stage);
      button.classList.toggle("complete", name === "vote" ? sealed : name === "verify" ? Boolean(snapshot?.verification?.ok) : Boolean(snapshot?.audit));
      if (name === state.stage) button.setAttribute("aria-current", "step");
      else button.removeAttribute("aria-current");
    }
    for (const name of ["record", "anchor", "checkpoint", "receipt"]) {
      const link = $(`export-${name}`);
      link.setAttribute("aria-disabled", String(!sealed || busy));
      link.tabIndex = sealed && !busy ? 0 : -1;
    }
  }

  function setProof(id, status, label) {
    const item = $(id);
    item.classList.remove("pass", "fail");
    if (status) item.classList.add(status);
    item.querySelector(".trail-status").textContent = label;
    const mark = item.querySelector(".trail-mark");
    if (status === "pass") checkSymbol(mark);
    else mark.textContent = status === "fail" ? "!" : String(Array.from(item.parentNode.children).indexOf(item) + 1);
  }

  function checkSymbol(element) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 20 20");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "m4 10 4 4 8-8");
    svg.append(path);
    element.replaceChildren(svg);
  }

  function listErrors(id, errors) {
    const list = $(id);
    list.replaceChildren();
    for (const message of errors || []) {
      const item = document.createElement("li");
      item.textContent = String(message);
      list.append(item);
    }
    list.hidden = !list.children.length;
  }

  function renderVerification(result) {
    const inProgress = working(state.snapshot) && state.snapshot.job.operation === "verify";
    $("verification-result").hidden = !result || inProgress;
    $("verification-next").hidden = !result || inProgress;
    $("published-tally").hidden = true;
    if (inProgress) {
      for (const id of ["proof-encryption", "proof-recording", "proof-inclusion", "proof-tally"]) setProof(id, "", "Checking…");
      return;
    }
    if (!result) return;
    const passed = result.ok === true;
    $("verification-result").className = `result-card${passed ? "" : " failure"}`;
    if (passed) checkSymbol($("verification-symbol"));
    else $("verification-symbol").textContent = "!";
    $("verification-label").textContent = passed ? "Supplied evidence · verified" : "Supplied evidence · failed";
    $("verification-title").textContent = passed ? "The evidence checks out." : "The evidence failed its checks.";
    $("verification-summary").textContent = passed
      ? "The existing verifier checked ballot proofs, signed records, your ciphertext's inclusion, and the published tally. These supplied files agree. Independent custody is still inconclusive."
      : "The existing verifier found inconsistent or invalid evidence. This result does not establish a trustworthy election.";
    listErrors("verification-errors", result.errors);
    setProof("proof-encryption", result.crypto_valid === true ? "pass" : "fail", result.crypto_valid === true ? "Proofs checked" : "Check failed");
    setProof("proof-recording", result.recorded === true && passed ? "pass" : "fail", result.recorded === true && passed ? "Signature checked" : "Not established");
    setProof("proof-inclusion", result.included === true ? "pass" : "fail", result.included === true ? "Exact match" : "No match");
    setProof("proof-tally", result.tally_verified === true ? "pass" : "fail", result.tally_verified === true ? "Proofs checked" : "Check failed");
    const garden = result.totals?.garden;
    const library = result.totals?.library;
    if (passed && !inProgress && Number.isInteger(garden) && Number.isInteger(library) && garden >= 0 && library >= 0 && garden + library === 100) {
      $("published-tally").hidden = false;
      $("garden-count").textContent = String(garden);
      $("library-count").textContent = String(library);
    }
  }

  function renderAudit(result) {
    $("audit-result").hidden = !result || working(state.snapshot) && state.snapshot.job.operation === "audit";
    if (!result) return;
    const detection = ["DETECTED", "NOT DETECTED", "INCONCLUSIVE"].includes(result.detection) ? result.detection : "INCONCLUSIVE";
    const detected = detection === "DETECTED";
    const undetected = detection === "NOT DETECTED";
    $("audit-result").className = `result-card audit-result ${detected ? "detected" : undetected ? "undetected" : "inconclusive"}`;
    $("audit-symbol").textContent = detected ? "!" : undetected ? "?" : "…";
    $("audit-label").textContent = detection;
    $("audit-title").textContent = detected ? "The changed record leaves a trace." : undetected ? "No observation. No proof of omission." : "There isn't enough evidence.";
    $("audit-summary").textContent = result.explanation || "Review the supplied evidence. No additional claim is established by this interface.";
    $("audit-evidence").textContent = result.evidence || "No exposing evidence was returned.";
    $("audit-trust").textContent = result.trustworthy_party || "No trustworthy-party requirement was returned.";
    $("audit-ablation").textContent = result.without_retained_evidence || "INCONCLUSIVE";
    const verification = result.retained_evidence || result.first_observation;
    // Expose actual error strings in the detected case; hide an empty list.
    listErrors("audit-errors", verification?.errors);
  }

  function render(snapshot) {
    if (!snapshot || typeof snapshot !== "object" || !["ready", "working", "recorded", "verified"].includes(snapshot.phase)) {
      throw new Error("The demo returned an unknown state. No verification result has been established.");
    }
    state.snapshot = snapshot;
    const receipt = snapshot.receipt?.payload;
    $("receipt-hash").textContent = receipt?.ballot_hash || "The server has not returned a receipt yet.";
    $("receipt-status").textContent = receipt ? "Receipt returned" : "Waiting";
    $("sealed-chip").textContent = hasElection() ? "100 synthetic ballots · closed" : "Preparing the evidence";
    if (!snapshot.verification) {
      setProof("proof-encryption", "", "Not checked");
      setProof("proof-recording", "", receipt ? "Receipt returned" : "Not checked");
      setProof("proof-inclusion", snapshot.inclusion?.included === true ? "pass" : "", snapshot.inclusion?.included === true ? "Exact match" : "Not checked");
      setProof("proof-tally", "", "Not checked");
    }
    renderVerification(snapshot.verification);
    renderAudit(snapshot.audit);
    renderControls();
  }

  function completedMessage(snapshot, operation) {
    if (operation === "vote") return snapshot?.receipt && snapshot.cast_count === 100
      ? "100 synthetic ballots recorded. Your encrypted ballot fingerprint is ready."
      : "No completed ballot record was returned. No successful cast is established.";
    if (operation === "verify") return snapshot.verification?.ok === true ? "The supplied evidence passed the existing verifier." : "Verification returned a failure. Read the evidence below.";
    if (operation === "audit") return `Audit result: ${snapshot.audit?.detection || "INCONCLUSIVE"}. This is detection, not prevention.`;
    return "Connected to the fictional research demonstration.";
  }

  async function poll(operation) {
    if (state.polling) return;
    state.polling = true;
    let failures = 0;
    try {
      while (working(state.snapshot)) {
        await sleep(900);
        let snapshot;
        try {
          snapshot = await request("/api/demo/state");
          failures = 0;
          clearError();
        } catch (error) {
          failures += 1;
          showError(`${error.message} The check may still be running; retrying the status request.`, failures >= 5);
          activity("Connection interrupted. No new result is being claimed.", "error");
          if (failures >= 5) return;
          continue;
        }
        render(snapshot);
        if (working(snapshot)) {
          activity(snapshot.job.message || "The cryptographic job is still running…", "busy");
        }
      }
      if (state.snapshot?.job?.status === "error") {
        throw new Error(state.snapshot.job.message || "The cryptographic job could not finish.");
      }
      activity(completedMessage(state.snapshot, operation), "success");
      if (operation === "vote" && hasElection()) setStage("verify");
      if (operation === "verify" && state.snapshot?.verification) $("verification-result").scrollIntoView({ block: "nearest", behavior: "auto" });
      if (operation === "audit" && state.snapshot?.audit) $("audit-result").scrollIntoView({ block: "nearest", behavior: "auto" });
    } catch (error) {
      showError(error.message, true);
      activity("The operation did not complete. No passing result is being claimed.", "error");
    } finally {
      state.polling = false;
      state.busy = false;
      renderControls();
    }
  }

  async function operate(operation, body, message) {
    if (state.busy || working(state.snapshot)) return;
    state.busy = true;
    clearError();
    activity(message, "busy");
    renderControls();
    try {
      const snapshot = await request(`/api/demo/${operation}`, body);
      render(snapshot);
      if (working(snapshot)) await poll(operation);
      else {
        activity(completedMessage(snapshot, operation), "success");
        if (operation === "vote" && hasElection()) setStage("verify");
      }
    } catch (error) {
      showError(error.message, true);
      activity("The request did not complete. You can retry; no success is being claimed.", "error");
    } finally {
      state.busy = false;
      renderControls();
    }
  }

  async function connect() {
    if (state.busy || state.polling) return;
    state.busy = true;
    clearError();
    activity("Connecting to the research demo…", "busy");
    renderControls();
    try {
      const snapshot = await request("/api/demo/state");
      render(snapshot);
      if (snapshot.verification) setStage("verify", false);
      else if (hasElection()) setStage("verify", false);
      else if (snapshot.phase === "ready") setStage("vote", false);
      if (working(snapshot)) await poll(snapshot.job.operation);
      else if (snapshot.job?.status === "error") throw new Error(snapshot.job.message);
      else activity(hasElection() ? "Your fictional election is still available in this temporary session." : "Ready for your fictional choice. No personal information needed.", "success");
    } catch (error) {
      showError(error.message, true);
      activity("Unable to reach the demo. Live evidence is unavailable.", "error");
    } finally {
      state.busy = false;
      renderControls();
    }
  }

  document.querySelectorAll("[data-stage]").forEach((button) => button.addEventListener("click", () => setStage(button.dataset.stage)));
  document.querySelectorAll("input[name=choice]").forEach((input) => input.addEventListener("change", renderControls));
  document.querySelectorAll(".export-links a").forEach((link) => link.addEventListener("click", (event) => { if (link.getAttribute("aria-disabled") === "true") event.preventDefault(); }));
  $("vote-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const choice = new FormData(event.currentTarget).get("choice");
    if (!["garden", "library"].includes(choice)) return;
    operate("vote", { choice }, "Encrypting your ballot and 99 other synthetic ballots. Real checks may take a minute…");
  });
  $("verify-button").addEventListener("click", () => operate("verify", {}, "Running the existing ElectionGuard, signature, inclusion, and tally checks…"));
  $("to-audit").addEventListener("click", () => setStage("audit"));
  $("attack-delete").addEventListener("click", () => operate("audit", { attack: "witnessed-delete" }, "Computing a valid smaller tally, then comparing it with the retained checkpoint…"));
  $("attack-suppress").addEventListener("click", () => operate("audit", { attack: "unobserved-suppression" }, "Checking a branch where the first trustworthy observation omits a submission…"));
  $("retry-button").addEventListener("click", connect);
  $("copy-receipt").addEventListener("click", async () => {
    const fingerprint = state.snapshot?.receipt?.payload?.ballot_hash;
    if (!fingerprint) return;
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(fingerprint);
      activity("Encrypted ballot fingerprint copied. It contains no vote choice.", "success");
    } catch {
      activity("Clipboard access is unavailable. You can select and copy the fingerprint above.");
    }
  });
  $("restart-button").addEventListener("click", async () => {
    if (state.busy || working(state.snapshot)) return;
    await operate("reset", {}, "Forgetting this temporary synthetic election…");
    if (state.snapshot?.phase === "ready") {
      $("vote-form").reset();
      $("technical-evidence").open = false;
      setStage("vote");
      activity("A fresh fictional election is ready. The previous session has been forgotten.", "success");
    }
  });
  connect();
})();
