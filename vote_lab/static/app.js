"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { election: null, busy: false, receipt: null, verification: null };
  const attackHelp = {
    duplicate: "A copied ballot should fail uniqueness and record-integrity checks.",
    unauthorized: "A ballot without an eligible voter's authorization should be rejected.",
    deleted: "Missing ballots are detectable against a previously retained checkpoint or receipt. A verifier needs that external evidence.",
    modified: "Changing an encrypted ballot should break its proof, authorization, or recorded hash.",
    "invalid-proof": "A stronger adversary creates an invalid proof and re-signs the voter, operator, and witness wrappers. Cryptographic proof verification must still detect the failure.",
    "operator-retally": "The operator removes a ballot and produces a valid smaller tally. A separately retained witness checkpoint is needed to detect that omission.",
    "operator-forgery": "Explore what an operator can do with compromised authority keys, and which voter authorizations still constrain it.",
    "checkpoint-rewrite": "The operator signs a replacement witness checkpoint with its own key. Verification must reject a signature from the wrong authority."
  };

  async function request(path, body) {
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "same-origin"
    });
    let result;
    try { result = await response.json(); }
    catch { throw new Error("The local server returned an unreadable response."); }
    if (!response.ok) throw new Error(result.error || `The local request failed (${response.status}).`);
    return result;
  }

  function activity(message, type = "") {
    $("activity-text").textContent = message;
    $("activity").className = `activity ${type}`;
  }

  async function action(message, callback, done) {
    if (state.busy) return;
    state.busy = true;
    document.body.classList.add("working");
    document.querySelector(".experiment-grid").setAttribute("aria-busy", "true");
    $("connection-error").hidden = true;
    activity(message, "busy");
    renderControls();
    try {
      await callback();
      activity(typeof done === "function" ? done() : done || "Local experiment updated.", "success");
    } catch (error) {
      $("connection-error").textContent = error.message;
      $("connection-error").hidden = false;
      activity("The operation did not complete. Review the message above.");
    } finally {
      state.busy = false;
      document.body.classList.remove("working");
      document.querySelector(".experiment-grid").removeAttribute("aria-busy");
      renderControls();
    }
  }

  function renderControls() {
    const election = state.election;
    const sealed = election?.phase === "sealed";
    const open = election?.phase === "open";
    const voters = election?.voters || [];
    const chosenVoter = voters.find((voter) => voter.id === $("voter").value);
    const available = voters.some((voter) => !voter.voted);
    const busy = state.busy;
    $("voter").disabled = busy || !open || !available;
    $("choice-fieldset").disabled = busy || !open || !available;
    $("cast-button").disabled = busy || !open || !chosenVoter || chosenVoter.voted;
    $("simulate-button").disabled = busy || !open || !available;
    $("seal-button").disabled = busy || !open || !election?.cast_count;
    $("seal-button").textContent = sealed ? "Election closed & tally published" : "Close & tally election";
    $("verify-button").disabled = busy || !sealed;
    $("attack-button").disabled = busy || !sealed;
    $("attack").disabled = busy || !sealed;
    $("receipt-select").disabled = busy || !state.receipt;
    $("inclusion-button").disabled = busy || !state.receipt;
    $("mode").disabled = busy;
    $("reset-button").disabled = busy || !election;
    $("reset-confirm").disabled = busy;
    for (const name of ["record", "anchor", "checkpoint", "receipts"]) {
      const enabled = !busy && Boolean(election) && (name === "anchor" || (name === "receipts" ? Boolean(election.cast_count) : sealed));
      $(`export-${name}`).setAttribute("aria-disabled", String(!enabled));
      $(`export-${name}`).tabIndex = enabled ? 0 : -1;
    }
  }

  function renderElection(election, preferredReceipt = null) {
    state.election = election;
    const sealed = election.phase === "sealed";
    const count = Number(election.cast_count) || 0;
    const total = Number(election.eligible_count) || 100;
    $("cast-count").textContent = count;
    $("eligible-count").textContent = total;
    $("count-bar").style.width = `${Math.min(100, Math.max(0, count / total * 100))}%`;
    $("phase-chip").textContent = sealed ? "Election closed" : "Open for simulated ballots";
    $("phase-chip").className = `chip${sealed ? " closed" : ""}`;
    $("mode-chip").textContent = election.mode === "receiver" ? "Receiver-owned authorization" : "Baseline voter signatures";
    $("mode").value = election.mode || "baseline";
    $("election-id").textContent = election.election_id || "—";
    $("casting-status").textContent = sealed ? "This election is closed. Start a new experiment to cast more synthetic ballots." : count >= total ? "All 100 simulated identities have voted. Close the election to compute its tally." : "Ballots are encrypted before they enter the public record.";

    const oldVoter = $("voter").value;
    $("voter").replaceChildren();
    for (const voter of election.voters || []) {
      const option = document.createElement("option");
      option.value = voter.id;
      option.textContent = `${voter.id}${voter.voted ? " · already voted" : " · eligible"}`;
      option.disabled = Boolean(voter.voted);
      $("voter").append(option);
    }
    const retainVoter = election.voters?.find((voter) => voter.id === oldVoter && !voter.voted);
    $("voter").value = retainVoter ? oldVoter : election.voters?.find((voter) => !voter.voted)?.id || "";

    $("receipt-select").replaceChildren();
    for (const receipt of election.receipts || []) {
      const option = document.createElement("option");
      option.value = receipt.ballot_id;
      option.textContent = receipt.voter_id || receipt.ballot_id;
      $("receipt-select").append(option);
    }
    const selected = preferredReceipt || election.receipts?.find((receipt) => receipt.ballot_id === state.receipt?.ballot_id) || election.receipts?.at(-1);
    selectReceipt(selected || null);
    const totals = election.totals;
    $("tally-results").hidden = !totals;
    $("tally-empty").hidden = Boolean(totals);
    if (totals) {
      const garden = Number(totals.garden) || 0;
      const library = Number(totals.library) || 0;
      const castTotal = garden + library;
      $("garden-total").textContent = garden;
      $("library-total").textContent = library;
      $("result-count").textContent = `${castTotal} counted ${castTotal === 1 ? "ballot" : "ballots"}`;
      $("garden-bar").style.width = `${castTotal ? garden / castTotal * 100 : 0}%`;
      $("library-bar").style.width = `${castTotal ? library / castTotal * 100 : 0}%`;
    }
    $("step-cast").className = sealed ? "complete" : "current";
    $("step-tally").className = sealed ? "complete" : count > 0 ? "current" : "";
    $("step-verify").className = state.verification?.ok ? "complete" : sealed ? "current" : "";
    $("step-attack").className = sealed ? "current" : "";
    $("verification-empty").querySelector("p").textContent = sealed ? "The published tally is ready for independent verification." : "Close the election to enable verification.";
    if (election.verification && !state.verification) renderVerification(election.verification);
    renderControls();
  }

  function selectReceipt(receipt) {
    state.receipt = receipt;
    $("receipt-empty").hidden = Boolean(receipt);
    $("receipt-details").hidden = !receipt;
    $("inclusion-result").hidden = true;
    if (receipt) {
      $("receipt-select").value = receipt.ballot_id;
      $("receipt-id").textContent = receipt.ballot_id;
      $("receipt-hash").textContent = receipt.ballot_hash;
    }
    renderControls();
  }

  function populateList(id, values) {
    const list = $(id);
    list.replaceChildren();
    for (const value of values || []) {
      const item = document.createElement("li");
      item.textContent = String(value);
      list.append(item);
    }
    list.hidden = !values?.length;
  }

  function renderVerification(result) {
    state.verification = result;
    $("verification-empty").hidden = true;
    $("verification-result").hidden = false;
    $("verification-result").className = `verification-result${result.ok ? "" : " failure"}`;
    $("verification-heading").textContent = result.ok ? "Public record verification passed" : "Public record verification failed";
    $("verification-summary").textContent = result.ok ? "The supplied evidence is internally consistent with the retained anchor and checkpoint. This is not a guarantee of a safe real election." : "The record did not satisfy the verification requirements. Review the failures below.";
    populateList("verification-checks", result.checks);
    populateList("verification-errors", result.errors);
    $("step-verify").className = result.ok ? "complete" : "current";
  }

  function clearResults() {
    state.verification = null;
    state.receipt = null;
    $("verification-empty").hidden = false;
    $("verification-result").hidden = true;
    $("attack-result").hidden = true;
    $("inclusion-result").hidden = true;
  }

  $("voter").addEventListener("change", renderControls);
  $("receipt-select").addEventListener("change", () => selectReceipt(state.election.receipts.find((receipt) => receipt.ballot_id === $("receipt-select").value)));
  $("cast-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const voterId = $("voter").value;
    const choice = new FormData(event.currentTarget).get("choice");
    action(`Encrypting a ballot for ${voterId} and checking eligibility…`, async () => {
      const result = await request("/api/cast", { voter_id: voterId, choice });
      renderElection(result.state || result, result.receipt?.payload || result.receipt);
    }, `Ballot accepted for ${voterId}. Its inclusion receipt is ready.`);
  });

  $("simulate-button").addEventListener("click", () => action("Encrypting and checking the remaining synthetic ballots. This may take a moment…", async () => {
    const result = await request("/api/simulate", {});
    renderElection(result.state || result);
  }, "All simulated voters have cast one ballot. Close the election to tally."));

  $("seal-button").addEventListener("click", () => action("Closing the synthetic election and producing the tally evidence…", async () => {
    const result = await request("/api/seal", {});
    renderElection(result.state || result);
  }, "Election closed. The published result is ready for independent verification."));

  $("verify-button").addEventListener("click", () => action("Independently checking ballot authorizations, proofs, frozen record, and tally…", async () => {
    renderVerification(await request("/api/verify", {}));
  }, () => state.verification?.ok ? "The supplied public evidence passed verification." : "Verification detected a failure in the supplied evidence."));

  $("inclusion-button").addEventListener("click", () => action("Checking the receipt against the encrypted ballot record…", async () => {
    const result = await request("/api/inclusion", { ballot_id: state.receipt.ballot_id, ballot_hash: state.receipt.ballot_hash });
    $("inclusion-result").hidden = false;
    $("inclusion-result").className = `message${result.included ? "" : " error"}`;
    $("inclusion-result").textContent = `${result.included ? "Ballot included. " : "Ballot not found or changed. "}${result.explanation || ""}`;
  }, "Receipt inclusion check complete. Inclusion alone does not verify voter intent."));

  $("attack").addEventListener("change", () => {
    $("attack-help").textContent = attackHelp[$("attack").value];
    $("attack-result").hidden = true;
  });

  $("attack-button").addEventListener("click", () => action("Mutating a copy of the sealed record and checking the changed evidence…", async () => {
    const result = await request("/api/attack", { attack: $("attack").value });
    const detected = result.detected === undefined ? !result.ok : result.detected;
    $("attack-result").hidden = false;
    $("attack-result").className = `attack-result${detected ? "" : " undetected"}`;
    $("attack-result-icon").textContent = detected ? "✓" : "!";
    $("attack-result-title").textContent = detected ? "Tampering detected by the verifier" : "This attack was not detected";
    $("attack-result-explanation").textContent = result.explanation || (detected ? "The altered evidence failed the checks below." : "The supplied evidence cannot distinguish this attack. Read the research report for the relevant trust assumptions.");
    populateList("attack-errors", result.errors);
  }, "Adversarial experiment complete. The result and its limitations appear below."));

  for (const name of ["record", "anchor", "checkpoint", "receipts"]) {
    $(`export-${name}`).addEventListener("click", (event) => {
      if (event.currentTarget.getAttribute("aria-disabled") === "true") event.preventDefault();
    });
  }

  $("reset-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (!state.busy) $("reset-dialog").showModal();
  });
  $("reset-cancel").addEventListener("click", () => $("reset-dialog").close());
  $("reset-confirm").addEventListener("click", () => {
    $("reset-dialog").close();
    const mode = $("mode").value;
    action("Creating a fresh election with new synthetic identities and keys…", async () => {
      const result = await request("/api/reset", { mode });
      clearResults();
      renderElection(result.state || result);
    }, "A fresh synthetic election is ready. All 100 fake voters are eligible.");
  });

  action("Connecting to the local research experiment…", async () => {
    renderElection(await request("/api/state"));
  }, "Local experiment ready. Cast a fake ballot or simulate the election.");
})();
