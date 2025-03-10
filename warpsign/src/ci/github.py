import requests
import base64
import json
from nacl import encoding, public
import uuid
import datetime
import time
from zipfile import ZipFile
from io import BytesIO


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

        print("\nWorkflow dispatch request details:")
        print(f"URL: {dispatch_url}")
        print(f"Data: {json.dumps(data, indent=2)}")

        try:
            response = requests.post(dispatch_url, headers=self.headers, json=data)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            error_msg = f"\nRequest failed: {e}"
            if hasattr(e, "response") and e.response is not None:
                error_msg += f"\nResponse status: {e.response.status_code}"
                error_msg += f"\nResponse body: {e.response.text}"
            raise Exception(error_msg) from e

        print(f"\nResponse status: {response.status_code}")
        print(f"Response body: {response.text}")

        # Add delay to allow GitHub to queue the workflow
        print("\nWaiting for GitHub to queue the workflow...")
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

    def wait_for_workflow(
        self, workflow_id: str, run_uuid: str = None, timeout: int = 1800
    ) -> dict:
        """Wait for workflow to complete and return the run data"""
        import time

        start_time = time.time()
        last_status = None
        last_conclusion = None
        found_run_id = None
        first_announcement = True

        while time.time() - start_time < timeout:
            # Get fresh run details each time
            run = self.get_workflow_run(workflow_id, run_uuid)
            if not run:
                time.sleep(5)
                continue

            # Store the run ID once we find it
            if found_run_id is None:
                found_run_id = run["id"]
            elif run["id"] != found_run_id:
                # Skip if we found a different run
                time.sleep(5)
                continue

            # Announce the run only once when we first find it
            if first_announcement:
                print(f"\nFound workflow run:")
                print(f"Run ID: {run['id']}")
                print(f"HTML URL: {run['html_url']}")
                print(f"Created at: {run['created_at']}")
                first_announcement = False

            # Get fresh status info
            status = run.get("status")
            conclusion = run.get("conclusion")

            # Only print status if it changed
            if status != last_status or conclusion != last_conclusion:
                print(f"\nWorkflow status: {status}")
                if conclusion:
                    print(f"Conclusion: {conclusion}")
                last_status = status
                last_conclusion = conclusion

                # Also get detailed run information
                run_detail_url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/runs/{run['id']}"
                run_response = requests.get(run_detail_url, headers=self.headers)
                if run_response.status_code == 200:
                    run_detail = run_response.json()
                    if run_detail.get("jobs_url"):
                        jobs_response = requests.get(
                            run_detail["jobs_url"], headers=self.headers
                        )
                        if jobs_response.status_code == 200:
                            jobs = jobs_response.json().get("jobs", [])
                            if jobs:
                                current_job = jobs[0]  # We only have one job.

            if status == "completed":
                if conclusion == "success":
                    return run
                elif conclusion == "failure":
                    error_msg = f"\nWorkflow failed!"
                    error_msg += f"\nView details at: https://github.com/{self.owner}/{self.repo}/actions/runs/{run['id']}"
                    raise Exception(error_msg)
                elif conclusion == "cancelled":
                    print("\nWorkflow was cancelled, exiting...")
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
                    print(f"Found URL in logs: {url}")
                    return {"url": url}

        print("\nNo URL found in logs.")
        return {}

    def get_run_logs(self, run_id: int) -> str:
        """Get the logs from a workflow run"""
        url = (
            f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/logs"
        )
        print(f"\nFetching logs from: {url}")

        # Get the redirect URL
        response = requests.get(url, headers=self.headers, allow_redirects=False)
        print(f"Initial response status: {response.status_code}")
        if response.status_code != 302:
            return "Could not fetch logs: No redirect found"

        # Get the logs zip file from the redirect URL
        logs_url = response.headers.get("Location")
        print(f"Redirect URL: {logs_url}")
        if not logs_url:
            return "Could not fetch logs: No download URL found"

        try:
            # Download the zip file
            print("Downloading logs zip file...")
            zip_response = requests.get(logs_url)
            zip_response.raise_for_status()
            print(f"Zip download status: {zip_response.status_code}")

            # Extract the sign.txt file from the zip
            print("Opening zip file...")
            with ZipFile(BytesIO(zip_response.content)) as zip_file:
                # Look specifically for 0_sign.txt
                if "0_sign.txt" in zip_file.namelist():
                    return zip_file.read("0_sign.txt").decode("utf-8")
                return "Could not find 0_sign.txt in logs"

        except Exception as e:
            print(f"Error getting logs: {str(e)}")
            return f"Could not fetch logs: {str(e)}"
