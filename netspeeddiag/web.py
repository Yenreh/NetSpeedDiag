"""
Flask dashboard and JSON API.

``GET  /``                      dashboard page
``GET  /api/config``            profiles, plan and target catalog
``GET  /api/progress``          live progress of the current run
``POST /api/runs``              start a run ``{"profile", "label", "notes"}``
``POST /api/cancel``            stop the current run after the running measurement
``GET  /api/runs``              run summaries, newest first
``GET  /api/runs.csv``          run summaries as CSV
``GET  /api/runs/<id>``         full run document
``GET  /api/runs/<id>/download`` run document as a JSON attachment
``DELETE /api/runs/<id>``       delete a run

No authentication: bind to localhost (the default).
"""

from __future__ import annotations

import json

from flask import Flask, Response, jsonify, render_template, request

from .runner import DiagnosticRunner
from .settings import VERSION, Settings
from .store import ResultStore


def create_app(settings: Settings, store: ResultStore, runner: DiagnosticRunner) -> Flask:
    """
    Build the Flask application.

    Args:
        settings: Application settings.
        store: Result store.
        runner: Diagnostic runner.

    Returns:
        The configured app.
    """
    app = Flask(__name__)

    @app.errorhandler(ValueError)
    def bad_request(error):
        """Map validation errors to HTTP 400."""
        return jsonify(error=str(error)), 400

    @app.errorhandler(RuntimeError)
    def conflict(error):
        """Map state errors (run already in progress) to HTTP 409."""
        return jsonify(error=str(error)), 409

    @app.get("/")
    def index():
        """Dashboard page."""
        return render_template("index.html", version=VERSION)

    @app.get("/api/config")
    def config():
        """Profiles, plan and the target catalog."""
        tests = settings.load_tests()
        return jsonify(
            version=VERSION,
            profiles=settings.profile_names(),
            default_profile=settings.default_profile,
            labels=tests.get("labels") or [],
            plan=settings.plan,
            targets={
                d: [{k: t.get(k) for k in ("id", "name", "type", "category")}
                    for t in (tests.get(d) or {}).get("targets") or []]
                for d in ("download", "upload")
            },
        )

    @app.get("/api/progress")
    def progress():
        """Live progress of the current (or last) run."""
        return jsonify(runner.progress())

    @app.post("/api/runs")
    def start_run():
        """Start a run in the background."""
        body = request.get_json(silent=True) or {}
        run_id = runner.start_background(
            profile=str(body.get("profile") or settings.default_profile),
            label=str(body.get("label") or "").strip()[:60],
            notes=str(body.get("notes") or "").strip()[:2000],
        )
        return jsonify(id=run_id), 202

    @app.post("/api/cancel")
    def cancel():
        """Request the running run to stop."""
        return jsonify(cancelled=runner.cancel())

    @app.get("/api/runs")
    def list_runs():
        """Run summaries, newest first."""
        return jsonify(store.list())

    @app.get("/api/runs.csv")
    def runs_csv():
        """Run summaries as CSV."""
        return Response(
            store.to_csv(), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=netspeeddiag-runs.csv"},
        )

    @app.get("/api/runs/<run_id>")
    def get_run(run_id: str):
        """Full run document."""
        doc = store.get(run_id)
        return jsonify(doc) if doc else (jsonify(error="Run not found"), 404)

    @app.get("/api/runs/<run_id>/download")
    def download_run(run_id: str):
        """Run document as a JSON attachment."""
        doc = store.get(run_id)
        if not doc:
            return jsonify(error="Run not found"), 404
        return Response(
            json.dumps(doc, indent=2), mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=netspeeddiag-{run_id}.json"},
        )

    @app.delete("/api/runs/<run_id>")
    def delete_run(run_id: str):
        """Delete a run."""
        if runner.progress().get("running") and runner.progress().get("id") == run_id:
            raise RuntimeError("Cannot delete the run in progress")
        return jsonify(deleted=store.delete(run_id))

    return app
