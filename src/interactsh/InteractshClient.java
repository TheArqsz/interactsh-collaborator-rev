package interactsh;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import lombok.Getter;

public class InteractshClient {
	private static final String SESSION_NOT_FOUND = "could not get correlation-id from cache";
	// zbase32: the only nonce characters interactsh-server >= 1.4.0 accepts.
	private static final String NONCE_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";

	private PrivateKey privateKey;
	private PublicKey publicKey;

	private static boolean isExtensionActive() {
		return burp.BurpExtender.api != null && !burp.BurpExtender.unloading;
	}

	private static void logError(String message) {
		if (isExtensionActive()) {
			burp.BurpExtender.api.logging().logToError(message);
		}
	}

	@Getter
	private final String correlationId;
	private final String secretKey;
	private final int nonceLength;
	private final String testAesMode;
	private volatile String probeLabel;
	private volatile boolean probeSeen;
	private final String pubKeyBase64;
	// Decryption failures since the last register() or verifyCallback() call.
	private final AtomicInteger decryptFailures = new AtomicInteger();
	// Message for the UI about the most recent decryption failure, taken once by the listener.
	private final AtomicReference<String> pendingDecryptNotice = new AtomicReference<>();

	private String host;
	private int port;
	private boolean scheme;
	@Getter
	private volatile boolean registered;
	@Getter
	private volatile boolean sessionLost;
	@Getter
	private volatile String lastError;
	private String authorization;

	/** A decrypted record together with the AES mode that produced it. */
	static final class Decrypted {
		final String mode;
		final byte[] raw;
		final String plain;

		Decrypted(String mode, byte[] raw) {
			this.mode = mode;
			this.raw = raw;
			this.plain = new String(raw, StandardCharsets.UTF_8).trim();
		}
	}

	/** Thrown when a record does not decrypt to JSON under the configured AES mode. */
	static final class AesModeException extends Exception {
		private static final long serialVersionUID = 1L;

		AesModeException(String message) {
			super(message);
		}
	}

	public InteractshClient() {
		this(burp.gui.Config.getHost(), savedPort(), burp.gui.Config.getScheme(), burp.gui.Config.getAuth(),
				burp.gui.Config.getCidLength(), burp.gui.Config.getCidNonceLength(), null);
	}

	public static InteractshClient forTest(String host, int port, boolean tls, String token, int cidLength,
			int nonceLength, String aesMode) {
		return new InteractshClient(host, port, tls, token, cidLength, nonceLength, aesMode);
	}

	private InteractshClient(String host, int port, boolean tls, String token, int cidLength, int nonceLength,
			String testAesMode) {
		this.correlationId = UUID.randomUUID().toString().replace("-", "").substring(0, cidLength);
		this.nonceLength = nonceLength;
		this.secretKey = UUID.randomUUID().toString();
		this.testAesMode = testAesMode;

		KeyPair kp = generateKeys();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		this.pubKeyBase64 = Base64.getEncoder().encodeToString(getPublicKey().getBytes(StandardCharsets.UTF_8));

		this.host = host;
		this.scheme = tls;
		this.authorization = token;
		this.port = port;
	}

	private static int savedPort() {
		String configuredPort = burp.gui.Config.getPort();
		String validPort = burp.gui.Config.validPort(configuredPort, burp.gui.Config.getScheme());
		if (!validPort.equals(configuredPort.trim())) {
			burp.BurpExtender.api.logging().logToError(
					"Invalid port '" + configuredPort + "' in Configuration - using " + validPort + " instead.");
		}
		return Integer.parseInt(validPort);
	}

	public boolean register() {
		this.lastError = null;
		resetDecryptState();
		if (!isExtensionActive())
			return false;

		if (!hostResolves()) {
			this.lastError = "Cannot resolve host '" + host + "' - please check the server address in Configuration.";
			burp.BurpExtender.api.logging().logToError(lastError);
			return false;
		}

		try {
			JSONObject registerData = new JSONObject();
			registerData.put("public-key", pubKeyBase64);
			registerData.put("secret-key", secretKey);
			registerData.put("correlation-id", correlationId);

			String requestBody = registerData.toString();
			StringBuilder requestBuilder = new StringBuilder();

			requestBuilder.append("POST /register HTTP/1.1\r\n").append("Host: ").append(host)
					.append("\r\n").append("User-Agent: Interact.sh Client\r\n")
					.append("Content-Type: application/json\r\n").append("Content-Length: ")
					.append(requestBody.length()).append("\r\n");

			if (authorization != null && !authorization.isEmpty()) {
				requestBuilder.append("Authorization: ").append(authorization).append("\r\n");
			}

			requestBuilder.append("Connection: close\r\n\r\n").append(requestBody);

			String request = requestBuilder.toString();

			HttpService httpService = HttpService.httpService(host, port, scheme);
			HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
			burp.BurpExtender
					.debugLog("Sending registration request to " + host + ":" + port + " (TLS=" + scheme + ")");
			HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();
			burp.BurpExtender
					.debugLog("Registration response received: " + (resp != null ? resp.statusCode() : "null"));

			if (resp == null) {
				this.lastError = "No response from '" + host + ":" + port
						+ "' - check the port, TLS setting and that the server is running.";
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError("Registration failed: " + lastError);
				}
				return false;
			}

			if (resp.statusCode() == 200) {
				this.registered = true;
				this.sessionLost = false;
				burp.BurpExtender.debugLog("Session registration was successful.");
				return true;
			} else if (resp.statusCode() == 401) {
				burp.BurpExtender.debugLog("Registration rejected with status 401.");
				this.lastError = (authorization == null || authorization.isEmpty())
						? "Server requires a token - set Token in Configuration."
						: "Server rejected the token - check Token in Configuration.";
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError("Registration failed: " + lastError);
				}
			} else {
				burp.BurpExtender.debugLog("Registration failed with status " + resp.statusCode() + ": " + truncate(resp.bodyToString(), 200));
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError(
							"Registration failed with status " + resp.statusCode() + ": " + resp.bodyToString());
				}
			}
		} catch (Exception ex) {
			burp.BurpExtender.debugLog("Registration error: " + ex);
			this.lastError = isUnknownHost(ex)
					? "Cannot resolve host '" + host + "' - please check the server address in Configuration."
					: "Registration error: " + ex.getMessage();
			if (isExtensionActive()) {
				burp.BurpExtender.api.logging().logToError(lastError);
			}
		}
		return false;
	}

	private static String truncate(String s, int max) {
		return s == null || s.length() <= max ? String.valueOf(s) : s.substring(0, max);
	}

	private static boolean isUnknownHost(Throwable ex) {
		for (Throwable t = ex; t != null; t = t.getCause()) {
			if (t instanceof java.net.UnknownHostException) {
				return true;
			}
		}
		return false;
	}

	private boolean hostResolves() {
		try {
			java.net.InetAddress.getByName(host);
			return true;
		} catch (java.net.UnknownHostException e) {
			return false;
		}
	}

	public boolean verifyCallback() {
		String probeHost = getInteractDomain();
		this.probeSeen = false;
		this.decryptFailures.set(0);
		this.probeLabel = probeHost.substring(0, probeHost.indexOf('.'));
		burp.BurpExtender.debugLog("Verifying session with a test callback to " + probeHost);
		try {
			String request = "GET / HTTP/1.1\r\nHost: " + probeHost
					+ "\r\nUser-Agent: Interact.sh Client\r\nConnection: close\r\n\r\n";
			burp.BurpExtender.api.http()
					.sendRequest(HttpRequest.httpRequest(HttpService.httpService(host, port, scheme), request));
			for (int attempt = 0; attempt < 3 && !probeSeen; attempt++) {
				if (attempt > 0) {
					Thread.sleep(500);
				}
				poll();
			}
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		} catch (Exception ex) {
			burp.BurpExtender.debugLog("Session verification request failed: " + ex.getMessage());
		}
		return probeSeen;
	}

	public boolean poll() {
		if (!isExtensionActive())
			return false;

		StringBuilder requestBuilder = new StringBuilder();

		requestBuilder.append("GET /poll?id=").append(correlationId).append("&secret=")
				.append(secretKey).append(" HTTP/1.1\r\n").append("Host: ").append(host)
				.append("\r\n").append("User-Agent: Interact.sh Client\r\n");

		if (authorization != null && !authorization.isEmpty()) {
			requestBuilder.append("Authorization: ").append(authorization).append("\r\n");
		}

		requestBuilder.append("Connection: close\r\n\r\n");

		String request = requestBuilder.toString();

		HttpResponse resp;
		try {
			HttpService httpService = HttpService.httpService(host, port, scheme);
			HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
			resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();
		} catch (Exception ex) {
			burp.BurpExtender.debugLog("Poll: request error: " + ex);
			if (isExtensionActive()) {
				burp.BurpExtender.api.logging().logToError(isUnknownHost(ex)
						? "Poll failed - cannot resolve host '" + host + "'."
						: "Poll failed - request error: " + ex.getMessage());
			}
			return false;
		}
		if (resp == null || resp.statusCode() != 200) {
			String body = (resp != null) ? resp.bodyToString() : null;
			this.sessionLost = body != null && body.contains(SESSION_NOT_FOUND);
			burp.BurpExtender.debugLog("Poll: HTTP " + (resp != null ? resp.statusCode() : "no response"));
			if (isExtensionActive()) {
				burp.BurpExtender.api.logging().logToError("Poll failed - status: "
						+ (resp != null ? resp.statusCode() : "no response")
						+ (sessionLost ? " (session unknown to server)" : ""));
			}
			return false;
		}

		String responseBody = resp.bodyToString();
		if (responseBody == null || responseBody.isEmpty()) {
			burp.BurpExtender.debugLog("Poll: HTTP 200, 0 records (empty response)");
			return true;
		}

		try {
			JSONObject jsonObject = new JSONObject(responseBody);
			String aesKey = jsonObject.getString("aes_key");
			byte[] key = this.decryptAesKey(aesKey);
			int dataCount = 0;
			JSONArray data = jsonObject.optJSONArray("data");
			if (data != null) {
				dataCount = data.length();
				processRecords(data, key, this::handleDecrypted);
			}
			// Token-scoped interactions (FTP, SMB, Responder, LDAP full logging) are
			// returned unencrypted in a separate field.
			int extraCount = arrayLength(jsonObject, "extra");
			int tlddataCount = arrayLength(jsonObject, "tlddata");
			addPlainInteractions(jsonObject, "extra", false);
			addPlainInteractions(jsonObject, "tlddata", true);
			burp.BurpExtender.debugLog("Poll: HTTP 200, " + (dataCount + extraCount + tlddataCount) + " records (data "
					+ dataCount + ", extra " + extraCount + ", tlddata " + tlddataCount + ")");
		} catch (Exception ex) {
			burp.BurpExtender.debugLog("Poll: could not process response: " + ex);
			if (isExtensionActive()) {
				String msg = isUnknownHost(ex)
						? "Cannot resolve host '" + host + "' - please check the server address in Configuration."
						: "Polling error: " + ex.getMessage();
				burp.BurpExtender.api.logging().logToError(msg);
			}
		}
		return true;
	}

	private static int arrayLength(JSONObject object, String key) {
		JSONArray array = object.optJSONArray(key);
		return array == null ? 0 : array.length();
	}

	private void handleDecrypted(Decrypted decrypted) {
		if (probeLabel != null && decrypted.plain.contains(probeLabel)) {
			probeSeen = true;
			return;
		}
		if (isExtensionActive() && testAesMode == null) {
			burp.BurpExtender.addToTable(new InteractshEntry(decrypted.plain));
		}
	}

	/**
	 * Decrypts and handles each record independently: a record that fails to
	 * decrypt or parse is logged and skipped, so the rest of the batch is still
	 * processed. Returns the number of records that failed.
	 */
	int processRecords(JSONArray data, byte[] key, Consumer<Decrypted> sink) {
		int failures = 0;
		for (int i = 0; i < data.length(); i++) {
			Decrypted decrypted;
			try {
				decrypted = decryptData(data.getString(i), key);
			} catch (AesModeException ex) {
				failures++;
				recordDecryptFailure(ex.getMessage());
				continue;
			} catch (Exception ex) {
				failures++;
				String msg = "Could not decrypt an interaction: " + ex.getMessage();
				burp.BurpExtender.debugLog("Record " + i + " decrypt failed: " + ex);
				recordDecryptFailure(msg);
				continue;
			}
			try {
				sink.accept(decrypted);
			} catch (Exception ex) {
				failures++;
				String msg = "Could not parse interaction (AES mode " + decrypted.mode + ", plaintext starts \""
						+ preview(decrypted.raw) + "\"): " + ex.getMessage();
				burp.BurpExtender.debugLog(msg);
				logError(msg);
			}
		}
		return failures;
	}

	private void recordDecryptFailure(String message) {
		decryptFailures.incrementAndGet();
		pendingDecryptNotice.set(message);
		logError(message);
	}

	private void resetDecryptState() {
		decryptFailures.set(0);
		pendingDecryptNotice.set(null);
	}

	/** Number of records that failed to decrypt since the last register() or verifyCallback(). */
	public int getDecryptFailures() {
		return decryptFailures.get();
	}

	/** Returns the pending decryption failure message once, or null if there is none. */
	public String takeDecryptNotice() {
		return pendingDecryptNotice.getAndSet(null);
	}

	public void deregister() {
		// Runs during unload too, so it only needs the API handle, not an active
		// extension.
		burp.api.montoya.MontoyaApi api = burp.BurpExtender.api;
		if (api == null)
			return;

		try {
			JSONObject deregisterData = new JSONObject();
			deregisterData.put("correlation-id", correlationId);
			deregisterData.put("secret-key", secretKey);
			String requestBody = deregisterData.toString();

			StringBuilder requestBuilder = new StringBuilder();

			requestBuilder.append("POST /deregister HTTP/1.1\r\n").append("Host: ").append(host)
					.append("\r\nUser-Agent: Interact.sh Client\r\n")
					.append("Content-Type: application/json\r\n").append("Content-Length: ")
					.append(requestBody.length()).append("\r\n");

			if (authorization != null && !authorization.isEmpty()) {
				requestBuilder.append("Authorization: ").append(authorization).append("\r\n");
			}

			requestBuilder.append("Connection: close\r\n\r\n").append(requestBody);

			String request = requestBuilder.toString();

			HttpService httpService = HttpService.httpService(host, port, scheme);
			HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
			HttpResponse resp = api.http().sendRequest(httpRequest).response();
			this.registered = false;
			if (resp == null || resp.statusCode() != 200) {
				api.logging().logToError("Deregistration failed - status: "
						+ (resp != null ? resp.statusCode() : "no response"));
			} else {
				burp.BurpExtender.debugLog("Session " + correlationId + " deregistered.");
			}
		} catch (Exception ex) {
			this.registered = false;
			try {
				String msg = isUnknownHost(ex)
						? "Cannot resolve host '" + host + "' - please check the server address in Configuration."
						: "Deregister error: " + ex.getMessage();
				api.logging().logToError(msg);
			} catch (Exception ignore) {
			}
		}
	}

	public String getInteractDomain() {
		if (correlationId == null || correlationId.isEmpty()) {
			return "";
		} else {
			String fullDomain = correlationId;

			Random random = new Random();
			while (fullDomain.length() < correlationId.length() + nonceLength) {
				fullDomain += NONCE_ALPHABET.charAt(random.nextInt(NONCE_ALPHABET.length()));
			}

			fullDomain += "." + host;
			return fullDomain;
		}
	}

	private void addPlainInteractions(JSONObject pollResponse, String field, boolean wildcard) {
		if (testAesMode != null || pollResponse.isNull(field)) {
			return;
		}
		JSONArray interactions = pollResponse.getJSONArray(field);
		for (int i = 0; i < interactions.length(); i++) {
			if (!isExtensionActive())
				break;
			try {
				InteractshEntry entry = new InteractshEntry(interactions.getString(i));
				if (wildcard && entry.uid.toLowerCase().contains(correlationId)) {
					continue;
				}
				entry.wildcard = wildcard;
				burp.BurpExtender.addToTable(entry);
			} catch (Exception ex) {
				burp.BurpExtender.api.logging()
						.logToError("Could not parse " + field + " interaction: " + ex.getMessage());
			}
		}
	}

	private KeyPair generateKeys() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			return kpg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			burp.BurpExtender.api.logging().logToError("Unable to generate client key pair", e);
			throw new RuntimeException(e);
		}
	}

	private String getPublicKey() {
		String pubKey = "-----BEGIN PUBLIC KEY-----\n";
		String[] chunks = splitStringEveryN(Base64.getEncoder().encodeToString(publicKey.getEncoded()), 64);
		for (String chunk : chunks) {
			pubKey += chunk + "\n";
		}
		pubKey += "-----END PUBLIC KEY-----\n";
		return pubKey;
	}

	private byte[] decryptAesKey(String encrypted) throws Exception {
		byte[] cipherTextArray = Base64.getDecoder().decode(encrypted);

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
		OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1",
				new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
		return cipher.doFinal(cipherTextArray);
	}

	Decrypted decryptData(String input, byte[] key) throws Exception {
		String configured = (testAesMode != null) ? testAesMode : burp.gui.Config.getAesMode();
		String mode = (configured == null || configured.isEmpty()) ? "AUTO" : configured.toUpperCase();

		if (!"AUTO".equals(mode)) {
			Decrypted decrypted = decryptWithMode(input, key, mode);
			if (!isJsonDocument(decrypted.plain)) {
				burp.BurpExtender.debugLog("Record did not decrypt as JSON with AES mode " + mode
						+ "; plaintext starts \"" + preview(decrypted.raw) + "\"");
				throw new AesModeException("Could not decrypt interaction with AES mode " + mode
						+ "; the server likely uses a different mode, try AUTO.");
			}
			return decrypted;
		}

		// AUTO: try CTR first (public servers), then CFB (self-hosted servers).
		for (String candidate : new String[] { "CTR", "CFB" }) {
			try {
				Decrypted decrypted = decryptWithMode(input, key, candidate);
				if (isJsonDocument(decrypted.plain)) {
					burp.BurpExtender.debugLog("AUTO picked AES mode " + candidate + ".");
					return decrypted;
				}
				burp.BurpExtender.debugLog("AUTO: " + candidate + " did not produce JSON; plaintext starts \""
						+ preview(decrypted.raw) + "\"");
			} catch (Exception ex) {
				burp.BurpExtender.debugLog("AUTO: " + candidate + " decryption threw: " + ex);
			}
		}

		throw new AesModeException("Could not decrypt interaction with AES mode AUTO (tried CTR and CFB); "
				+ "the server likely uses a different mode, set AES Mode to the one the server uses.");
	}

	private Decrypted decryptWithMode(String input, byte[] key, String mode) throws Exception {
		byte[] cipherTextArray = Base64.getDecoder().decode(input);
		if (cipherTextArray.length <= 16) {
			throw new IllegalArgumentException("encrypted record is too short");
		}
		byte[] iv = Arrays.copyOfRange(cipherTextArray, 0, 16);
		byte[] cipherText = Arrays.copyOfRange(cipherTextArray, 16, cipherTextArray.length);

		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/" + mode + "/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
		return new Decrypted(mode, cipher.doFinal(cipherText));
	}

	private static boolean isJsonDocument(String value) {
		if (!looksLikeJson(value)) {
			return false;
		}
		try {
			if (value.startsWith("{")) {
				new JSONObject(value);
			} else {
				new JSONArray(value);
			}
			return true;
		} catch (JSONException ex) {
			return false;
		}
	}

	private static boolean looksLikeJson(String value) {
		if (value == null) {
			return false;
		}
		String candidate = value.trim();
		return (candidate.startsWith("{") && candidate.endsWith("}"))
				|| (candidate.startsWith("[") && candidate.endsWith("]"));
	}

	/** First 16 bytes of plaintext with non-printable bytes escaped, for logs. */
	static String preview(byte[] raw) {
		StringBuilder sb = new StringBuilder();
		int n = Math.min(16, raw.length);
		for (int i = 0; i < n; i++) {
			int b = raw[i] & 0xff;
			if (b >= 0x20 && b < 0x7f) {
				sb.append((char) b);
			} else {
				sb.append(String.format("\\x%02x", b));
			}
		}
		return sb.toString();
	}

	private String[] splitStringEveryN(String s, int interval) {
		int arrayLength = (int) Math.ceil(((s.length() / (double) interval)));
		String[] result = new String[arrayLength];

		int j = 0;
		int lastIndex = result.length - 1;
		for (int i = 0; i < lastIndex; i++) {
			result[i] = s.substring(j, j + interval);
			j += interval;
		}
		result[lastIndex] = s.substring(j);

		return result;
	}
}
