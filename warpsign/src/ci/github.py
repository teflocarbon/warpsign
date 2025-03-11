import requests
import base64
import json
from nacl import encoding, public
import uuid
import datetime
import time
from zipfile import ZipFile
from io import BytesIO
from typing import Dict, Callable, List, Optional

from warpsign.logger import get_console

console = get_console()


class GitHubHandler:
    def __init__(self, owner, repo, token):
        self.owner = owner
        self.repo = repo
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get_public_key(self):
        url = (
            f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/secrets/public-key"
        )
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def encrypt_secret(self, public_key: str, secret_value: str) -> str:
        public_key = public.PublicKey(
            base64.b64decode(public_key.encode("utf-8")), encoding.RawEncoder
        )
        sealed_box = public.SealedBox(public_key)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")

    def update_secret(self, secret_name: str, secret_value: str):
        key_data = self.get_public_key()
        encrypted_value = self.encrypt_secret(key_data["key"], secret_value)

        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/secrets/{secret_name}"
        data = {"encrypted_value": encrypted_value, "key_id": key_data["key_id"]}

        response = requests.put(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.status_code in (201, 204)

    def trigger_workflow(self, workflow_id: str, inputs: dict):
        """Trigger a workflow and return tracking UUID"""
        workflow_url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_id}"
        workflow_response = requests.get(workflow_url, headers=self.headers)

        if workflow_response.status_code == 404:
            raise Exception(f"Workflow file '{workflow_id}' not found in repository")
        workflow_response.raise_for_status()

        # Add UUID to inputs for tracking
        run_uuid = str(uuid.uuid4())
        inputs["run_uuid"] = run_uuid

        dispatch_url = f"{workflow_url}/dispatches"
        data = {"ref": "main", "inputs": inputs}

        console.print("\nWorkflow dispatch request details:")
        console.print(f"Data: {json.dumps(data, indent=2)}")

        try:
            response = requests.post(dispatch_url, headers=self.headers, json=data)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            error_msg = f"\nRequest failed: {e}"
            if hasattr(e, "response") and e.response is not None:
                error_msg += f"\nResponse status: {e.response.status_code}"
                error_msg += f"\nResponse body: {e.response.text}"
            raise Exception(error_msg) from e

        console.print(f"\nResponse status: {response.status_code}")
        console.print(f"Response body: {response.text}")

        # Add delay to allow GitHub to queue the workflow
        console.print("\nWaiting for GitHub to queue the workflow...")
        time.sleep(5)

        return run_uuid

    # GitHub Actions is bullshit and doesn't provide a way to get the run when triggering a workflow?
    # How did that get into production?

    def get_workflow_run(self, workflow_id: str, run_uuid=None):
        """Get the run for a workflow matching the UUID"""
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_id}/runs"
        params = {
            "exclude_pull_requests": "true",
            "per_page": 30,  # Increased to get more runs
            "created": f">{datetime.datetime.utcnow() - datetime.timedelta(minutes=5):%Y-%m-%dT%H:%M:%SZ}",
        }

        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()

        runs = response.json().get("workflow_runs", [])

        if not runs:
            return None

        if run_uuid:
            # Sort runs by created_at in descending order
            runs.sort(key=lambda x: x.get("created_at", ""), reverse=True)

            for run in runs:
                # Check if UUID is in the run name (format: [uuid])
                run_name = run.get("name", "")
                if run_name.startswith("[") and run_name.endswith("]"):
                    workflow_uuid = run_name[1:-1]  # Remove brackets
                    if workflow_uuid == run_uuid:
                        return run

            return None

        # If no UUID specified, return newest non-cancelled run
        for run in runs:
            if run.get("status") != "completed" or run.get("conclusion") != "cancelled":
                return run

        return runs[0] if runs else None

    # This code is awful, but it works and GitHub's API is a pain.

    def get_workflow_steps(self, run_id: int) -> list:
        """Get details about the steps in a workflow run"""
        url = (
            f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/jobs"
        )
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()

        jobs_data = response.json()
        steps = []

        for job in jobs_data.get("jobs", []):
            for step in job.get("steps", []):
                steps.append(
                    {
                        "name": step.get("name", "Unknown step"),
                        "status": step.get("status", "unknown"),
                        "conclusion": step.get("conclusion", None),
                        "number": step.get("number", 0),
                        "started_at": step.get("started_at", None),
                        "completed_at": step.get("completed_at", None),
                    }
                )

        return steps

    def log_current_steps(self, run_id: int, previous_steps=None, step_callbacks=None):
        """Log currently running steps and trigger callbacks for specific steps.

        Args:
            run_id: The workflow run ID
            previous_steps: The previous steps state for comparison
            step_callbacks: Dict mapping step names to callback functions.
                           Callbacks will be called with the step data as argument
                           when that step is found to be running or just completed.
        """
        try:
            steps = self.get_workflow_steps(run_id)
            if not steps:
                return previous_steps

            # Find steps that are in_progress
            active_steps = [s for s in steps if s["status"] == "in_progress"]
            completed_steps = [
                s
                for s in steps
                if s["status"] == "completed"
                and s["conclusion"] not in ["skipped", None]
            ]

            # Run callbacks for matching steps
            if step_callbacks:
                for step in active_steps:
                    step_name = step["name"]
                    if step_name in step_callbacks:
                        console.print(f"\n[blue]Detected step running: {step_name}[/]")
                        step_callbacks[step_name](step, "running")

                # Check for newly completed steps with callbacks
                if previous_steps:
                    for step in completed_steps:
                        step_name = step["name"]
                        if step_name in step_callbacks and not any(
                            ps["name"] == step_name and ps["status"] == "completed"
                            for ps in previous_steps
                        ):
                            console.print(
                                f"\n[green]Detected step completed: {step_name}[/]"
                            )
                            step_callbacks[step_name](step, "completed")

            # Only print if there are new active steps or newly completed steps
            if previous_steps is None or steps != previous_steps:
                # Print currently running steps
                if active_steps:
                    console.print("\n[bold blue][RUNNING STEPS][/]")
                    for step in active_steps:
                        console.print(f"→ {step['name']}")

                # Print recently completed steps (that weren't in previous update)
                if previous_steps:
                    new_completed = []
                    for step in completed_steps:
                        if not any(
                            ps["name"] == step["name"] and ps["status"] == "completed"
                            for ps in previous_steps
                        ):
                            new_completed.append(step)

                    if new_completed:
                        console.print("\n[bold green][COMPLETED STEPS][/]")
                        for step in new_completed:
                            status_icon = (
                                "✅" if step["conclusion"] == "success" else "❌"
                            )
                            status_color = (
                                "green" if step["conclusion"] == "success" else "red"
                            )
                            console.print(
                                f"[{status_color}]{status_icon} {step['name']}[/]"
                            )

            return steps
        except Exception as e:
            console.print(f"[red]Could not fetch step information: {str(e)}[/]")
            return previous_steps

    def wait_for_workflow(
        self,
        workflow_id: str,
        run_uuid: str = None,
        timeout: int = 1800,
        step_callbacks=None,
    ) -> dict:
        """Wait for workflow to complete and return the run data.

        Args:
            workflow_id: The workflow ID to wait for
            run_uuid: The UUID for the specific run to track
            timeout: Maximum time to wait in seconds
            step_callbacks: Dict mapping step names to callback functions
                          that will be called when those steps run or complete
        """
        import time

        start_time = time.time()
        last_status = None
        last_conclusion = None
        found_run_id = None
        first_announcement = True
        previous_steps = None

        while time.time() - start_time < timeout:
            # Get fresh run details each time
            run = self.get_workflow_run(workflow_id, run_uuid)
            if not run:
                time.sleep(5)
                continue

            # Store the run ID once we find it
            if found_run_id is None:
                found_run_id = run["id"]
                console.print(f"\n[bold cyan][WORKFLOW RUN DETAILS][/]")
                console.print(f"Run ID: {run['id']}")
                console.print(
                    f"HTML URL: [link={run['html_url']}]{run['html_url']}[/link]"
                )
                console.print(f"Created at: {run['created_at']}")
                first_announcement = False
            elif run["id"] != found_run_id:
                # Skip if we found a different run
                time.sleep(5)
                continue

            # Only print announcement once when we first find the run
            if first_announcement:
                console.print(f"\n[bold cyan][WORKFLOW RUN DETAILS][/]")
                console.print(f"Run ID: {run['id']}")
                console.print(
                    f"HTML URL: [link={run['html_url']}]{run['html_url']}[/link]"
                )
                console.print(f"Created at: {run['created_at']}")
                first_announcement = False

            # Get fresh status info
            status = run.get("status")
            conclusion = run.get("conclusion")

            # Only print status if it changed
            if status != last_status or conclusion != last_conclusion:
                console.print(f"\n[bold yellow][WORKFLOW STATUS UPDATE][/]")
                console.print(f"Status: {status}")
                if conclusion:
                    conclusion_color = (
                        "green"
                        if conclusion == "success"
                        else "red" if conclusion == "failure" else "yellow"
                    )
                    console.print(f"Conclusion: [{conclusion_color}]{conclusion}[/]")
                last_status = status
                last_conclusion = conclusion

            # Log current steps
            if found_run_id:
                previous_steps = self.log_current_steps(
                    found_run_id, previous_steps, step_callbacks
                )

            if status == "completed":
                if conclusion == "success":
                    console.print("\n[bold green][WORKFLOW COMPLETED][/]")
                    console.print("[green]✅ Workflow completed successfully![/]")
                    return run
                elif conclusion == "failure":
                    error_msg = f"\n[bold red][ERROR] Workflow failed![/]"
                    error_msg += f"\nView details at: [link=https://github.com/{self.owner}/{self.repo}/actions/runs/{run['id']}]https://github.com/{self.owner}/{self.repo}/actions/runs/{run['id']}[/link]"
                    console.print(error_msg)
                    raise Exception(
                        f"Workflow failed! View details at: https://github.com/{self.owner}/{self.repo}/actions/runs/{run['id']}"
                    )
                elif conclusion == "cancelled":
                    console.print(
                        "\n[bold yellow][WARNING] Workflow was cancelled, exiting...[/]"
                    )
                    raise Exception("Workflow was cancelled")

            time.sleep(5)

        raise TimeoutError("Workflow timed out")

    def get_workflow_outputs(self, run_id: int) -> dict:
        """Get the outputs from a workflow run"""
        logs = self.get_run_logs(run_id)
        for line in logs.splitlines():
            if "Final URL: " in line:
                url = line.split("Final URL: ", 1)[1].strip()
                # Ignore raw variable names
                if url and not url.startswith("$"):
                    console.print(f"Found URL in logs: [link={url}]{url}[/link]")
                    return {"url": url}

        console.print("\n[yellow]No URL found in logs.[/]")
        return {}

    def get_run_logs(self, run_id: int) -> str:
        """Get the logs from a workflow run"""
        url = (
            f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/logs"
        )
        console.print(f"\nFetching logs from: [dim]{url}[/]")

        # Get the redirect URL
        response = requests.get(url, headers=self.headers, allow_redirects=False)
        console.print(f"Initial response status: {response.status_code}")
        if response.status_code != 302:
            return "Could not fetch logs: No redirect found"

        # Get the logs zip file from the redirect URL
        logs_url = response.headers.get("Location")
        console.print(f"Redirect URL: [dim]{logs_url}[/]")
        if not logs_url:
            return "Could not fetch logs: No download URL found"

        try:
            # Download the zip file
            console.print("Downloading logs zip file...")
            zip_response = requests.get(logs_url)
            zip_response.raise_for_status()
            console.print(f"Zip download status: {zip_response.status_code}")

            # Extract the sign.txt file from the zip
            console.print("Opening zip file...")
            with ZipFile(BytesIO(zip_response.content)) as zip_file:
                # Look specifically for 0_sign.txt
                if "0_sign.txt" in zip_file.namelist():
                    return zip_file.read("0_sign.txt").decode("utf-8")
                return "Could not find 0_sign.txt in logs"

        except Exception as e:
            console.print(f"[red]Error getting logs: {str(e)}[/]")
            return f"Could not fetch logs: {str(e)}"
