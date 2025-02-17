import requests
import base64
import json
from nacl import encoding, public


class GitHubSecrets:
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
        """Trigger a workflow using the workflow_dispatch event"""
        # First verify the workflow exists
        workflow_url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_id}"
        workflow_response = requests.get(workflow_url, headers=self.headers)

        if workflow_response.status_code == 404:
            raise Exception(f"Workflow file '{workflow_id}' not found in repository")
        workflow_response.raise_for_status()

        # Trigger the workflow without checking for workflow_dispatch
        dispatch_url = f"{workflow_url}/dispatches"
        data = {"ref": "main", "inputs": inputs}

        print("\nWorkflow dispatch request details:")
        print(f"URL: {dispatch_url}")
        print(f"Headers: {json.dumps(self.headers, indent=2)}")
        print(f"Data: {json.dumps(data, indent=2)}")

        response = requests.post(dispatch_url, headers=self.headers, json=data)

        print(f"\nResponse status: {response.status_code}")
        print(f"Response body: {response.text}")

        response.raise_for_status()
        return True

    def get_workflow_run(self, workflow_id: str):
        """Get the latest run for a workflow"""
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_id}/runs"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        runs = response.json().get("workflow_runs", [])
        return runs[0] if runs else None

    def wait_for_workflow(self, workflow_id: str, timeout: int = 1800) -> dict:
        """Wait for workflow to complete and return the run data"""
        import time

        start_time = time.time()

        while time.time() - start_time < timeout:
            run = self.get_workflow_run(workflow_id)
            if not run:
                time.sleep(5)
                continue

            status = run.get("status")
            conclusion = run.get("conclusion")

            if status == "completed":
                if conclusion == "success":
                    return run
                else:
                    raise Exception(f"Workflow failed with conclusion: {conclusion}")

            time.sleep(5)

        raise TimeoutError("Workflow timed out")

    def get_workflow_outputs(self, run_id: int) -> dict:
        """Get the outputs from a workflow run"""
        url = (
            f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/jobs"
        )
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()

        jobs = response.json().get("jobs", [])
        if not jobs:
            return {}

        # Get the outputs from the last job
        steps = jobs[-1].get("steps", [])
        for step in steps:
            if step.get("name") == "Upload to Litterbox":
                outputs = step.get("outputs", {})
                return {"signed_ipa_url": outputs.get("url")}

        return {}
