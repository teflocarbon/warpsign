function setupDropzone(dropzoneId, inputId, filenameId) {
  const dropzone = document.getElementById(dropzoneId);
  const fileInput = document.getElementById(inputId);
  const filenameDisplay = document.getElementById(filenameId);

  dropzone.addEventListener("click", () => {
    fileInput.click();
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("highlight");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("highlight");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("highlight");

    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      updateFilename(fileInput, filenameDisplay);
    }
  });

  fileInput.addEventListener("change", () => {
    updateFilename(fileInput, filenameDisplay);
  });
}

function updateFilename(input, display) {
  if (input.files.length) {
    display.textContent = `Selected: ${input.files[0].name}`;

    // Add a subtle animation to the display
    display.style.opacity = "0";
    setTimeout(() => {
      display.style.opacity = "1";
    }, 50);
  }
}

function uploadCertificate(type, fileInputId, passwordId, messageId) {
  const fileInput = document.getElementById(fileInputId);
  const passwordInput = document.getElementById(passwordId);
  const password = passwordInput.value;
  const messageDiv = document.getElementById(messageId);
  const buttonId =
    type === "development" ? "dev-upload-btn" : "dist-upload-btn";
  const button = document.getElementById(buttonId);

  // Reset previous message
  messageDiv.textContent = "";
  messageDiv.className = "message-container";

  if (!fileInput.files.length) {
    messageDiv.className = "error-message";
    messageDiv.textContent = "Please select a certificate file.";
    return;
  }

  // Check if password is empty
  if (!password.trim()) {
    messageDiv.className = "error-message";
    messageDiv.textContent = "Your certificate must have a password.";
    passwordInput.classList.add("input-error");
    setTimeout(() => passwordInput.classList.remove("input-error"), 1500);
    return;
  }

  // Show loading state
  const originalText = button.textContent;
  button.textContent = "Uploading...";
  button.disabled = true;

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("certificate", file);
  formData.append("password", password);

  fetch(`/upload/${type}`, {
    method: "POST",
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        messageDiv.className = "success-message";
        messageDiv.textContent = "Certificate uploaded successfully!";
      } else {
        messageDiv.className = "error-message";
        messageDiv.textContent = data.error || "Upload failed.";
      }
    })
    .catch((error) => {
      messageDiv.className = "error-message";
      messageDiv.textContent = "An error occurred during upload.";
      console.error("Error:", error);
    })
    .finally(() => {
      // Restore button state
      button.textContent = originalText;
      button.disabled = false;
    });
}

// Setup dropzones
document.addEventListener("DOMContentLoaded", () => {
  setupDropzone("dev-dropzone", "dev-file-input", "dev-filename");
  setupDropzone("dist-dropzone", "dist-file-input", "dist-filename");

  // Button event listeners
  document.getElementById("dev-upload-btn").addEventListener("click", () => {
    uploadCertificate(
      "development",
      "dev-file-input",
      "dev-password",
      "dev-message"
    );
  });

  document.getElementById("dist-upload-btn").addEventListener("click", () => {
    uploadCertificate(
      "distribution",
      "dist-file-input",
      "dist-password",
      "dist-message"
    );
  });

  document.getElementById("done-btn").addEventListener("click", () => {
    fetch("/shutdown", { method: "POST" })
      .then(() => {
        window.close();
      })
      .catch(() => {
        // Even if the fetch fails (server already shutting down),
        // try to close the window
        window.close();
      });
  });
});
