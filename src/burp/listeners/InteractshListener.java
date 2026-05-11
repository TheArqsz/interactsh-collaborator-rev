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
	private volatile boolean stopped = false;

	public InteractshListener(Consumer<String> onReadyCallback, Consumer<String> onFailureCallback) {
		this.executor = Executors.newSingleThreadExecutor();
		this.executor.submit(() -> pollingLoop(onReadyCallback, onFailureCallback));
	}

	private void pollingLoop(Consumer<String> onReadyCallback, Consumer<String> onFailureCallback) {
		try {
			this.client = new InteractshClient();
			if (client.register()) {
				Thread.interrupted();
				if (onReadyCallback != null) {
					String newUrl = client.getInteractDomain();
					SwingUtilities.invokeLater(() -> onReadyCallback.accept(newUrl));
				}
				while (!stopped && !burp.BurpExtender.unloading) {
					client.poll();
					try {
						long pollTime = burp.BurpExtender.getPollTime();
						pollSignal.tryAcquire(pollTime, TimeUnit.SECONDS);
					} catch (InterruptedException e) {
						break;
					}
				}
			} else {
				String errorMsg = "Unable to register interactsh client. Check config.";
				if (burp.BurpExtender.api != null) {
					burp.BurpExtender.api.logging().logToError(errorMsg);
				}
				if (onFailureCallback != null) {
					SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
				}
			}
		} catch (Throwable ex) {
			String errorMsg = "Error during registration: " + ex;
			if (burp.BurpExtender.api != null) {
				burp.BurpExtender.api.logging().logToError(errorMsg);
			}
			if (onFailureCallback != null) {
				SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
			}
		} finally {
			if (!stopped && client != null && client.isRegistered()) {
				client.deregister();
			}
		}
	}

	public void close() {
		stopped = true;
		pollSignal.release();
		executor.shutdownNow();

		new Thread(() -> {
			try {
				if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
					if (burp.BurpExtender.api != null) {
						try {
							burp.BurpExtender.api.logging().logToError("Polling task did not terminate in time.");
						} catch (Exception ignore) {
						}
					}
				}
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}).start();
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
			} catch (Exception e) {
				if (burp.BurpExtender.api != null) {
					burp.BurpExtender.api.logging().logToError("Could not copy to system clipboard: " + e.getMessage());
				}
			}

			// Try to copy to the system selection clipboard (for Linux primary selection)
			try {
				java.awt.datatransfer.Clipboard systemSelection = java.awt.Toolkit.getDefaultToolkit()
						.getSystemSelection();
				if (systemSelection != null) {
					systemSelection.setContents(stringSelection, null);
					atLeastOneSucceeded = true;
				}
			} catch (Exception e) {
				if (burp.BurpExtender.api != null) {
					burp.BurpExtender.api.logging().logToError("Could not copy to system selection: " + e.getMessage());
				}
			}

			return atLeastOneSucceeded;

		} else {
			if (burp.BurpExtender.api != null) {
				burp.BurpExtender.api.logging()
						.logToError("Interact.sh client is not yet initialized or registered.");
			}
			return false;
		}
	}
}
