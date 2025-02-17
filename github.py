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
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_id}/dispatches"
        data = {"ref": "main", "inputs": inputs}

        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return True
