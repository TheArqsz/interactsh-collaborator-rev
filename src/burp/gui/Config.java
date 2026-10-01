package burp.gui;

import burp.BurpExtender;
import burp.api.montoya.persistence.Preferences;

public class Config {

	private static final String DEFAULT_SERVER = "oast.live";
	private static final String DEFAULT_PORT = "443";
	private static final String DEFAULT_AUTHORIZATION = "";
	private static final String DEFAULT_POLL_INTERVAL = "60";
	private static final String DEFAULT_USES_TLS = "true";
	private static final String DEFAULT_AES_MODE = "AUTO";
	private static final String DEFAULT_DEBUG_LOGGING = "false";
	private static final String DEFAULT_HIDE_SHARED = "true";
	private static final String DEFAULT_HIDE_WILDCARD = "false";
	// Server defaults for -cidl and -cidn.
	private static final int DEFAULT_CID_LENGTH = 20;
	private static final int DEFAULT_CID_NONCE_LENGTH = 13;

	private static Preferences preferences() {
		return BurpExtender.api.persistence().preferences();
	}

	private static String getString(String key, String defaultValue) {
		String value = preferences().getString(key);
		return (value == null) ? defaultValue : value;
	}

	public static void generateConfig() {
		if (preferences().getString("interactsh-server") == null) {
			preferences().setString("interactsh-server", DEFAULT_SERVER);
			preferences().setString("interactsh-port", DEFAULT_PORT);
			preferences().setString("interactsh-authorization", DEFAULT_AUTHORIZATION);
			preferences().setString("interactsh-poll-time", DEFAULT_POLL_INTERVAL);
			preferences().setString("interactsh-uses-tls", DEFAULT_USES_TLS);
			preferences().setString("interactsh-aes-mode", DEFAULT_AES_MODE);
			preferences().setString("interactsh-debug-logging", DEFAULT_DEBUG_LOGGING);
			preferences().setString("interactsh-hide-shared", DEFAULT_HIDE_SHARED);
			preferences().setString("interactsh-hide-wildcard", DEFAULT_HIDE_WILDCARD);
			preferences().setString("interactsh-cid-length", String.valueOf(DEFAULT_CID_LENGTH));
			preferences().setString("interactsh-cid-nonce-length", String.valueOf(DEFAULT_CID_NONCE_LENGTH));
		}
	}

	public static void loadConfig() {
		String server = getString("interactsh-server", DEFAULT_SERVER);
		String port = getString("interactsh-port", DEFAULT_PORT);
		String tls = getString("interactsh-uses-tls", DEFAULT_USES_TLS);
		String authorization = getString("interactsh-authorization", DEFAULT_AUTHORIZATION);
		String pollInterval = getString("interactsh-poll-time", DEFAULT_POLL_INTERVAL);
		String aesMode = getString("interactsh-aes-mode", DEFAULT_AES_MODE);
		String debugLogging = getString("interactsh-debug-logging", DEFAULT_DEBUG_LOGGING);
		String hideShared = getString("interactsh-hide-shared", DEFAULT_HIDE_SHARED);

		InteractshTab.setServerText(server);
		InteractshTab.setPortText(port);
		InteractshTab.setAuthText(authorization);
		InteractshTab.setPollText(pollInterval);
		InteractshTab.setTlsBox(Boolean.parseBoolean(tls));
		InteractshTab.setAesModeText(aesMode);
		InteractshTab.setDebugLogging(Boolean.parseBoolean(debugLogging));
		InteractshTab.setHideShared(Boolean.parseBoolean(hideShared));
		InteractshTab.setHideWildcard(isHideWildcard());
		InteractshTab.setCidLengthText(String.valueOf(getCidLength()));
		InteractshTab.setCidNonceLengthText(String.valueOf(getCidNonceLength()));
	}

	public static void updateConfig() {
		String server = InteractshTab.getServerText();
		String port = InteractshTab.getPortText();
		String authorization = InteractshTab.getAuthText();
		String pollInterval = InteractshTab.getPollText();
		String tls = InteractshTab.getTlsBox();
		String aesMode = InteractshTab.getAesModeText();
		String debugLogging = InteractshTab.getDebugLogging();
		String hideShared = InteractshTab.getHideShared();

		preferences().setString("interactsh-server", server);
		preferences().setString("interactsh-port", port);
		preferences().setString("interactsh-uses-tls", tls);
		preferences().setString("interactsh-poll-time", pollInterval);
		preferences().setString("interactsh-authorization", authorization);
		preferences().setString("interactsh-aes-mode", aesMode);
		preferences().setString("interactsh-debug-logging", debugLogging);
		preferences().setString("interactsh-hide-shared", hideShared);
		preferences().setString("interactsh-hide-wildcard", InteractshTab.getHideWildcard());
		preferences().setString("interactsh-cid-length", InteractshTab.getCidLengthText().trim());
		preferences().setString("interactsh-cid-nonce-length", InteractshTab.getCidNonceLengthText().trim());
	}

	public static String getHost() {
		return getString("interactsh-server", DEFAULT_SERVER);
	}

	public static String getPort() {
		return getString("interactsh-port", DEFAULT_PORT);
	}

	public static String validPort(String port, boolean tls) {
		try {
			int value = Integer.parseInt(port.trim());
			if (value >= 1 && value <= 65535) {
				return String.valueOf(value);
			}
		} catch (NumberFormatException e) {
		}
		return tls ? "443" : "80";
	}

	public static boolean getScheme() {
		return Boolean.parseBoolean(getString("interactsh-uses-tls", DEFAULT_USES_TLS));
	}

	public static String getAuth() {
		return getString("interactsh-authorization", DEFAULT_AUTHORIZATION);
	}

	public static String getPollInterval() {
		return getString("interactsh-poll-time", DEFAULT_POLL_INTERVAL);
	}

	public static String getAesMode() {
		return getString("interactsh-aes-mode", DEFAULT_AES_MODE);
	}

	public static boolean isDebugEnabled() {
		return Boolean.parseBoolean(getString("interactsh-debug-logging", DEFAULT_DEBUG_LOGGING));
	}

	// The id is cut from a 32 character UUID; the server requires at least 3 for
	// both parts.
	public static int getCidLength() {
		return getLength("interactsh-cid-length", DEFAULT_CID_LENGTH, 32);
	}

	public static int getCidNonceLength() {
		return getLength("interactsh-cid-nonce-length", DEFAULT_CID_NONCE_LENGTH, 31);
	}

	private static int getLength(String key, int defaultValue, int max) {
		try {
			int value = Integer.parseInt(getString(key, String.valueOf(defaultValue)).trim());
			return (value >= 3 && value <= max) ? value : defaultValue;
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	public static boolean isHideWildcard() {
		return Boolean.parseBoolean(getString("interactsh-hide-wildcard", DEFAULT_HIDE_WILDCARD));
	}

	public static boolean isHideShared() {
		return Boolean.parseBoolean(getString("interactsh-hide-shared", DEFAULT_HIDE_SHARED));
	}
}
