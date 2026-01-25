package burp.listeners;

import java.awt.datatransfer.StringSelection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.swing.SwingUtilities;

import interactsh.InteractshClient;

public class InteractshListener {
	private final ExecutorService executor;
	private volatile InteractshClient client;
	private final Semaphore pollSignal = new Semaphore(0);

	public InteractshListener(Consumer<String> onReadyCallback, Consumer<String> onFailureCallback) {
		this.executor = Executors.newSingleThreadExecutor();
		this.executor.submit(() -> pollingLoop(onReadyCallback, onFailureCallback));
	}

	private void pollingLoop(Consumer<String> onReadyCallback, Consumer<String> onFailureCallback) {
		this.client = new InteractshClient();
		try {
			if (client.register()) {
				if (onReadyCallback != null) {
					String newUrl = client.getInteractDomain();
					SwingUtilities.invokeLater(() -> onReadyCallback.accept(newUrl));
				}
				while (!Thread.currentThread().isInterrupted()) {
					client.poll();
					try {
						long pollTime = burp.BurpExtender.getPollTime();
						pollSignal.tryAcquire(pollTime, TimeUnit.SECONDS);
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
				}
			} else {
				String errorMsg = "Unable to register interactsh client. Check config.";
				burp.BurpExtender.api.logging().logToError(errorMsg);
				if (onFailureCallback != null) {
					SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
				}
			}
		} catch (Exception ex) {
			String errorMsg = "Error during registration: " + ex.getMessage();
			burp.BurpExtender.api.logging().logToError(errorMsg, ex); // Log the full exception
			if (onFailureCallback != null) {
				SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
			}
		} finally {
			if (client != null && client.isRegistered()) {
				client.deregister();
			}
		}
	}

	public void close() {
		executor.shutdownNow();
		try {
			if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
				burp.BurpExtender.api.logging()
						.logToError("Polling task did not terminate in time.");
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	public boolean pollNowAll() {
		InteractshClient currentClient = this.client;
		if (currentClient != null && currentClient.isRegistered()) {
			pollSignal.release();
		}
		return currentClient != null && currentClient.isRegistered();
	}

	public boolean copyCurrentUrlToClipboard() {
		InteractshClient currentClient = this.client;
		if (currentClient != null && currentClient.isRegistered()) {
			String interactDomain = currentClient.getInteractDomain();
			StringSelection stringSelection = new StringSelection(interactDomain);

			boolean atLeastOneSucceeded = false;

			// Try to copy to the system clipboard (Windows, macOS, Linux clipboard)
			try {
				java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
				atLeastOneSucceeded = true;
				burp.BurpExtender.api.logging().logToOutput("Successfully copied to system clipboard.");
			} catch (Exception e) {
				burp.BurpExtender.api.logging().logToError("Could not copy to system clipboard: " + e.getMessage());
			}

			// Try to copy to the system selection clipboard (for Linux primary selection)
			try {
				java.awt.datatransfer.Clipboard systemSelection = java.awt.Toolkit.getDefaultToolkit()
						.getSystemSelection();
				if (systemSelection != null) {
					systemSelection.setContents(stringSelection, null);
					atLeastOneSucceeded = true;
					burp.BurpExtender.api.logging().logToOutput("Successfully copied to system selection.");
				}
			} catch (Exception e) {
				burp.BurpExtender.api.logging().logToError("Could not copy to system selection: " + e.getMessage());
			}

			return atLeastOneSucceeded;

		} else {
			burp.BurpExtender.api.logging()
					.logToError("Interact.sh client is not yet initialized or registered.");
			return false;
		}
	}
}
