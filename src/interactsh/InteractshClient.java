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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
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

	@Getter
	private final String correlationId;
	private final String secretKey;
	private final int nonceLength;
	private volatile String probeLabel;
	private volatile boolean probeSeen;
	private final String pubKeyBase64;

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
	private String aesMode;

	public InteractshClient() {
		this.correlationId = UUID.randomUUID().toString().replace("-", "").substring(0, burp.gui.Config.getCidLength());
		this.nonceLength = burp.gui.Config.getCidNonceLength();
		this.secretKey = UUID.randomUUID().toString();

		KeyPair kp = generateKeys();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		this.pubKeyBase64 = Base64.getEncoder().encodeToString(getPublicKey().getBytes(StandardCharsets.UTF_8));

		this.host = burp.gui.Config.getHost();
		this.scheme = burp.gui.Config.getScheme();
		this.authorization = burp.gui.Config.getAuth();
		this.aesMode = burp.gui.Config.getAesMode();
		String configuredPort = burp.gui.Config.getPort();
		String validPort = burp.gui.Config.validPort(configuredPort, this.scheme);
		if (!validPort.equals(configuredPort.trim())) {
			burp.BurpExtender.api.logging().logToError(
					"Invalid port '" + configuredPort + "' in Configuration - using " + validPort + " instead.");
		}
		this.port = Integer.parseInt(validPort);
	}

	public boolean register() {
		this.lastError = null;
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
				this.lastError = (authorization == null || authorization.isEmpty())
						? "Server requires a token - set Authorization in Configuration."
						: "Server rejected the token - check Authorization in Configuration.";
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError("Registration failed: " + lastError);
				}
			} else {
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError(
							"Registration failed with status " + resp.statusCode() + ": " + resp.bodyToString());
				}
			}
		} catch (Exception ex) {
			this.lastError = isUnknownHost(ex)
					? "Cannot resolve host '" + host + "' - please check the server address in Configuration."
					: "Registration error: " + ex.getMessage();
			if (isExtensionActive()) {
				burp.BurpExtender.api.logging().logToError(lastError);
			}
		}
		return false;
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
			if (isExtensionActive()) {
				burp.BurpExtender.api.logging().logToError("Poll failed - status: "
						+ (resp != null ? resp.statusCode() : "no response")
						+ (sessionLost ? " (session unknown to server)" : ""));
			}
			return false;
		}

		String responseBody = resp.bodyToString();
		if (responseBody == null || responseBody.isEmpty()) {
			return true;
		}

		try {
			JSONObject jsonObject = new JSONObject(responseBody);
			String aesKey = jsonObject.getString("aes_key");
			byte[] key = this.decryptAesKey(aesKey);
			if (!jsonObject.isNull("data")) {
				JSONArray data = jsonObject.getJSONArray("data");
				for (int i = 0; i < data.length(); i++) {
					String decryptedData = decryptData(data.getString(i), key);
					if (probeLabel != null && decryptedData.contains(probeLabel)) {
						probeSeen = true;
						continue;
					}
					if (isExtensionActive()) {
						InteractshEntry entry = new InteractshEntry(decryptedData);
						burp.BurpExtender.addToTable(entry);
					}
				}
			}
			// Token-scoped interactions (FTP, SMB, Responder, LDAP full logging) are
			// returned unencrypted in a separate field.
			addPlainInteractions(jsonObject, "extra", false);
			addPlainInteractions(jsonObject, "tlddata", true);
		} catch (Exception ex) {
			if (isExtensionActive()) {
				String msg = isUnknownHost(ex)
						? "Cannot resolve host '" + host + "' - please check the server address in Configuration."
						: "Polling error: " + ex.getMessage();
				burp.BurpExtender.api.logging().logToError(msg);
			}
		}
		return true;
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
		if (pollResponse.isNull(field)) {
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

	private String decryptData(String input, byte[] key) throws Exception {
		String mode = (this.aesMode == null || this.aesMode.isEmpty()) ? "AUTO" : this.aesMode.toUpperCase();

		if (!"AUTO".equals(mode)) {
			return decryptDataWithMode(input, key, mode);
		}

		// AUTO: try CTR first (public servers), then CFB (self-hosted servers).
		String lastResult = null;
		for (String candidate : new String[] { "CTR", "CFB" }) {
			try {
				String decrypted = decryptDataWithMode(input, key, candidate);
				if (looksLikeJson(decrypted)) {
					return decrypted;
				}
				lastResult = decrypted;
			} catch (Exception ignored) {
			}
		}

		return lastResult != null ? lastResult : "";
	}

	private String decryptDataWithMode(String input, byte[] key, String mode) throws Exception {
		byte[] cipherTextArray = Base64.getDecoder().decode(input);
		byte[] iv = Arrays.copyOfRange(cipherTextArray, 0, 16);
		byte[] cipherText = Arrays.copyOfRange(cipherTextArray, 16, cipherTextArray.length);

		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/" + mode + "/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
		byte[] decrypted = cipher.doFinal(cipherText);

		return new String(decrypted, StandardCharsets.UTF_8).trim();
	}

	private boolean looksLikeJson(String value) {
		if (value == null) {
			return false;
		}
		String candidate = value.trim();
		return (candidate.startsWith("{") && candidate.endsWith("}"))
				|| (candidate.startsWith("[") && candidate.endsWith("]"));
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
