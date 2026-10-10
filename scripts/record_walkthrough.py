#!/usr/bin/env python3
"""Record genuine local OpenLine Vote interactions as a 30-second phone video.

Requires already installed Playwright, Chromium, ffmpeg, and ffprobe. Start a
disposable loopback demo first. This script creates a new synthetic session,
casts a real ElectionGuard-encrypted demo ballot, requests verification, and
runs both live audit cases. A continuous raw recording is retained. The final
30-second MP4 keeps the genuine results readable and shortens the processing
waits. The edit is visibly disclosed and its source intervals are recorded;
processing delays are never replaced by fabricated success frames.
All recording artifacts are local review material, never publication approval.

If Playwright's downloaded ffmpeg is absent, the script automatically creates
an output-local resolver pointing to the existing system ffmpeg; it never
writes to your home cache or downloads a tool. Captions use an existing Open
Sans, DejaVu Sans, or Liberation Sans font, or a local file supplied with --font.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from public_browser_smoke import DemoRun, TIMEOUT, installed_browser, loopback_origin


def duration(path):
    process = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                              "-of", "json", str(path)], check=True, capture_output=True, text=True)
    return float(json.loads(process.stdout)["format"]["duration"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8002")
    parser.add_argument("--chromium")
    parser.add_argument("--font", type=Path, help="Existing local caption font; no font download")
    parser.add_argument("--out", type=Path, required=True, help="New directory for review-only recording artifacts")
    args = parser.parse_args()
    try:
        origin, executable = loopback_origin(args.url), installed_browser(args.chromium)
        from playwright.sync_api import expect, sync_playwright
    except (ValueError, ImportError) as exc:
        parser.error(str(exc))
    for binary in ("ffmpeg", "ffprobe"):
        if not shutil.which(binary):
            parser.error(f"Use an already installed {binary}; this script does not install tools")
    font = args.font or next((path for path in (
        Path("/usr/share/fonts/truetype/open-sans/OpenSans-Semibold.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"),
    ) if path.is_file()), None)
    if font is None or not font.is_file():
        parser.error("Supply --font with an existing local caption font")
    if args.out.exists():
        parser.error("Use a new --out directory; recordings are never overwritten")
    args.out.mkdir(parents=True)
    # Playwright normally looks for its downloaded ffmpeg build even when a
    # compatible system ffmpeg is already present. Reuse that local binary in
    # a disposable resolver directory instead of downloading another tool.
    import playwright as installed_playwright
    manifest = Path(installed_playwright.__file__).parent / "driver/package/browsers.json"
    revision = next(item["revision"] for item in json.loads(manifest.read_text())["browsers"] if item["name"] == "ffmpeg")
    if not str(revision).isdigit():
        parser.error("Unexpected installed Playwright ffmpeg revision")
    resolver = args.out.resolve() / "local-playwright-tools"
    tool_dir = resolver / ("ffmpeg-" + str(revision))
    tool_dir.mkdir(parents=True)
    (tool_dir / "ffmpeg-linux").symlink_to(shutil.which("ffmpeg"))
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(resolver)
    events = []
    scenes = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable, headless=True, args=["--no-sandbox"])
        context = browser.new_context(viewport={"width": 390, "height": 844},
                                      record_video_dir=str(args.out), record_video_size={"width": 390, "height": 844},
                                      reduced_motion="reduce", device_scale_factor=1)
        page = context.new_page()
        started = time.monotonic()
        def clock():
            return time.monotonic() - started
        def capture(label, seconds, target):
            begin = clock()
            page.wait_for_timeout(seconds * 1000)
            scenes.append({"label": label, "raw_start": begin, "raw_end": clock(), "edited_seconds": target})
        run = DemoRun(page, origin)
        page.goto(origin)
        expect(page.locator("#choice-fieldset")).to_be_enabled(timeout=TIMEOUT)
        vote_start = clock()
        page.wait_for_timeout(800)
        page.locator("#demo").evaluate("node => node.scrollIntoView({block: 'start'})")
        page.locator("input[value=garden]").check()
        page.wait_for_timeout(2200)
        scenes.append({"label": "Fictional choice", "raw_start": vote_start, "raw_end": clock(), "edited_seconds": 4})
        events.append({"event": "Fictional choice selected", "raw_seconds": clock()})
        page.locator("#vote-button").click()
        capture("Excerpt of genuine processing", 1.7, 2)
        voted = run.complete("vote")
        assert voted["job"]["status"] == "complete" and voted["inclusion"]["included"]
        expect(page.locator("#verify-button")).to_be_enabled(timeout=TIMEOUT)
        page.locator("#receipt-hash").scroll_into_view_if_needed()
        capture("Actual public receipt", 3.2, 4)
        events.append({"event": "Real encrypted ballot receipt returned", "raw_seconds": clock()})
        page.locator("#verify-button").click()
        verified = run.complete("verify")
        assert verified["verification"]["ok"] and verified["verification"]["tally_verified"]
        expect(page.locator("#verification-result")).to_be_visible(timeout=TIMEOUT)
        expect(page.locator("#published-tally")).to_be_visible()
        for choice in ("garden", "library"):
            expect(page.locator(f"#{choice}-count")).to_have_text(str(verified["verification"]["totals"][choice]))
        assert sum(verified["verification"]["totals"].values()) == 100
        page.locator("#verification-result").scroll_into_view_if_needed()
        capture("Actual verification result", 3.6, 4)
        events.append({"event": "Actual ElectionGuard evidence verification passed", "raw_seconds": clock()})
        page.locator("#to-audit").click()
        page.locator("#attack-delete").click()
        expect(page.locator("#audit-result")).to_be_hidden()
        deleted = run.complete("audit", attack="witnessed-delete")
        assert deleted["audit"]["detection"] == "DETECTED"
        expect(page.locator("#audit-label")).to_have_text("DETECTED", timeout=TIMEOUT)
        page.locator("#audit-result").scroll_into_view_if_needed()
        capture("Actual detected deletion", 4.6, 5)
        page.screenshot(path=str(args.out / "audit-detected.png"), full_page=True)
        events.append({"event": "Witnessed deletion detected by actual evidence comparison", "raw_seconds": clock()})
        page.locator("#attack-suppress").click()
        expect(page.locator("#audit-result")).to_be_hidden()
        suppressed = run.complete("audit", attack="unobserved-suppression")
        assert suppressed["audit"]["detection"] == "NOT DETECTED"
        expect(page.locator("#audit-label")).to_have_text("NOT DETECTED", timeout=TIMEOUT)
        page.locator("#audit-result").scroll_into_view_if_needed()
        capture("Actual undetected suppression", 4.6, 5)
        page.screenshot(path=str(args.out / "audit-undetected.png"), full_page=True)
        events.append({"event": "Suppression before observation not detected", "raw_seconds": clock()})
        page.locator("#limits-heading").scroll_into_view_if_needed()
        capture("Unsolved risks and custody limitation", 5.4, 6)
        final_viewports = []
        # Final UI checks use this same already verified record. These extra
        # review frames remain in the raw capture but are outside the short edit.
        page.locator("[data-stage=verify]").click()
        for width, height in ((320, 812), (375, 812), (390, 844), (1440, 1000)):
            page.set_viewport_size({"width": width, "height": height})
            run.no_overflow()
            page.screenshot(path=str(args.out / f"verified-{width}.png"), full_page=True)
            final_viewports.append({"width": width, "height": height, "final_verified_no_overflow": True})
        run.healthy()
        raw_path = Path(page.video.path())
        context.close()
        browser.close()
    raw_duration = duration(raw_path)
    caption = "Genuine local run | processing shortened"
    labels = "".join(f"[source{index}]" for index in range(len(scenes)))
    filters = [f"[0:v]split={len(scenes)}{labels}"]
    for index, scene in enumerate(scenes):
        length = scene["raw_end"] - scene["raw_start"]
        factor = scene["edited_seconds"] / length
        filters.append(f"[source{index}]trim=start={scene['raw_start']:.6f}:end={scene['raw_end']:.6f},"
                       f"setpts=(PTS-STARTPTS)*{factor:.12f},fps=30,"
                       f"tpad=stop_mode=clone:stop_duration=0.2,trim=duration={scene['edited_seconds']}[scene{index}]")
    clips = "".join(f"[scene{index}]" for index in range(len(scenes)))
    filters.append(f"{clips}concat=n={len(scenes)}:v=1:a=0,"
                   "drawbox=x=0:y=ih-42:w=iw:h=42:color=0x101a17@0.96:t=fill,"
                   f"drawtext=fontfile={font}:text='{caption}':fontcolor=white:fontsize=13:x=(w-tw)/2:y=h-29[edited]")
    output = args.out / "openline-vote-30s.mp4"
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-i", str(raw_path),
                    "-filter_complex", ";".join(filters), "-map", "[edited]", "-an", "-t", "30", "-c:v", "libx264", "-preset", "medium",
                    "-crf", "20", "-threads", "2", "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(output)], check=True)
    final_duration = duration(output)
    assert abs(final_duration - 30) < 0.1, final_duration
    metadata = {"result": "PASS", "scope": "Review-only real local synthetic interactions; not published",
                "raw_recording": raw_path.name, "raw_duration_seconds": raw_duration,
                "final_video": output.name, "final_duration_seconds": final_duration,
                "visible_edit_disclosure": caption,
                "frame_source": "Selected intervals of the continuous Playwright capture; no substituted success frames",
                "edited_source_intervals": scenes,
                "api_responses": run.responses, "events": events,
                "final_ui_validation": {"viewports": final_viewports, "displayed_tally_matches_actual_verifier": True,
                                        "published_ballot_count": 100, "audit_prior_result_hidden_while_working": True,
                                        "browser": "Headless Linux Chromium; physical phones and Safari not tested"},
                "live_results": {"ballot_included": voted["inclusion"]["included"],
                                 "cryptographic_verification": verified["verification"]["ok"],
                                 "witnessed_deletion": deleted["audit"]["detection"],
                                 "pre_observation_suppression": suppressed["audit"]["detection"]},
                "real_custody_status": "INCONCLUSIVE", "shared_account_isolation": "FAILED",
                "external_requests": 0, "external_api_spending": 0}
    metadata["recording_tool"] = "Existing system ffmpeg reused through a local Playwright resolver; no tool download"
    metadata["caption_font"] = str(font)
    (args.out / "walkthrough.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "video": str(output), "seconds": final_duration,
                      "raw_seconds": raw_duration, "editing": caption}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
