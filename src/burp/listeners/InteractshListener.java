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
	private volatile Consumer<Boolean> refreshCallback;
	// Decryption-failure toasts are shown once per session; reset by resetDecryptNotice().
	private volatile boolean decryptNoticeShown;
	private static final long MIN_REFRESH_GAP_MS = 1000;

	public InteractshListener(Consumer<String> onReadyCallback, Consumer<String> onFailureCallback) {
		this.executor = Executors.newSingleThreadExecutor();
		this.executor.submit(() -> pollingLoop(onReadyCallback, onFailureCallback));
	}

	private void pollingLoop(Consumer<String> onReadyCallback, Consumer<String> onFailureCallback) {
		try {
			this.client = new InteractshClient();
			if (client.register()) {
				Thread.interrupted();
				if (stopped) {
					burp.BurpExtender.debugLog("Discarding session " + client.getCorrelationId()
							+ ": listener was closed during registration.");
					return;
				}
				String newUrl = client.getInteractDomain();
				if (burp.BurpExtender.api != null) {
					burp.BurpExtender.api.logging().logToOutput("Session URL: " + newUrl);
				}
				if (client.verifyCallback()) {
					if (burp.BurpExtender.api != null) {
						burp.BurpExtender.api.logging()
								.logToOutput("Session verified: server recorded a test callback.");
					}
					if (onReadyCallback != null) {
						SwingUtilities.invokeLater(() -> onReadyCallback.accept(newUrl));
					}
				} else if (!stopped && !burp.BurpExtender.unloading) {
					boolean decryptProblem = client.getDecryptFailures() > 0;
					final String errorMsg = decryptProblem
						? "Session registered, but the server did not record a test callback. "
								+ "Check the correlation ID lengths and AES mode."
						: "Session registered, but the server did not record a test callback. "
								+ "Check that the correlation ID lengths match the server's -cidl/-cidn.";
					if (decryptProblem) {
						// This failure toast already reports the decryption problem.
						decryptNoticeShown = true;
						client.takeDecryptNotice();
					}
					if (burp.BurpExtender.api != null) {
						burp.BurpExtender.api.logging().logToError(errorMsg);
					}
					if (onFailureCallback != null) {
						SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
					}
				}
				while (!stopped && !burp.BurpExtender.unloading) {
					long pollTime = 60;
					long pollStarted = System.currentTimeMillis();
					Consumer<Boolean> onRefreshed = refreshCallback;
					refreshCallback = null;
					boolean polled = false;
					try {
						polled = client.poll();
						reportDecryptNotice(onFailureCallback);
						if (!polled && client.isSessionLost() && !stopped) {
							polled = client.register();
							resetDecryptNotice();
							if (polled && burp.BurpExtender.api != null) {
								burp.BurpExtender.api.logging()
										.logToOutput("Session was lost on the server and has been re-registered.");
							}
						}
						pollTime = burp.BurpExtender.getPollTime();
					} catch (RuntimeException ex) {
						if (stopped || burp.BurpExtender.unloading) {
							break;
						}
						if (burp.BurpExtender.api != null) {
							burp.BurpExtender.api.logging().logToError("Polling error: " + ex);
						}
					}
					if (onRefreshed != null && !stopped && !burp.BurpExtender.unloading) {
						boolean result = polled;
						SwingUtilities.invokeLater(() -> onRefreshed.accept(result));
					}
					try {
						if (pollSignal.tryAcquire(pollTime, TimeUnit.SECONDS)) {
							long wait = MIN_REFRESH_GAP_MS - (System.currentTimeMillis() - pollStarted);
							if (wait > 0 && !stopped) {
								Thread.sleep(wait);
							}
							pollSignal.drainPermits();
						}
					} catch (InterruptedException e) {
						break;
					}
				}
			} else if (!stopped) {
				String reason = client.getLastError();
				String errorMsg = (reason != null) ? reason : "Unable to register interactsh client. Check config.";
				if (reason == null && burp.BurpExtender.api != null) {
					burp.BurpExtender.api.logging().logToError(errorMsg);
				}
				if (onFailureCallback != null) {
					SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
				}
			}
		} catch (Throwable ex) {
			String errorMsg = (client != null && client.isRegistered())
					? "Polling stopped unexpectedly, regenerate the session: " + ex
					: "Error during registration: " + ex;
			if (burp.BurpExtender.api != null) {
				burp.BurpExtender.api.logging().logToError(errorMsg);
			}
			if (onFailureCallback != null) {
				SwingUtilities.invokeLater(() -> onFailureCallback.accept(errorMsg));
			}
		} finally {
			if (client != null && client.isRegistered()) {
				// close() interrupts this thread; clear the flag so the request can be sent.
				Thread.interrupted();
				client.deregister();
			}
		}
	}

	/** Shows the pending decryption-failure message, at most once per session. */
	private void reportDecryptNotice(Consumer<String> onFailureCallback) {
		String notice = client.takeDecryptNotice();
		if (notice == null || decryptNoticeShown) {
			return;
		}
		decryptNoticeShown = true;
		if (onFailureCallback != null) {
			SwingUtilities.invokeLater(() -> onFailureCallback.accept(notice));
		}
	}

	/** Allows the next decryption failure to be shown again, e.g. after the AES mode changed. */
	public void resetDecryptNotice() {
		decryptNoticeShown = false;
	}

	public void close() {
		stopped = true;
		pollSignal.release();
		executor.shutdownNow();

		new Thread(this::awaitTermination).start();
	}

	public void closeAndWait() {
		stopped = true;
		pollSignal.release();
		executor.shutdownNow();
		awaitTermination();
	}

	private void awaitTermination() {
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
	}

	public boolean pollNowAll(Consumer<Boolean> onResult) {
		InteractshClient currentClient = this.client;
		if (currentClient == null || !currentClient.isRegistered()) {
			return false;
		}
		refreshCallback = onResult;
		pollSignal.release();
		return true;
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
