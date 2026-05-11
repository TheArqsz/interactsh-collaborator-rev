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
	private PrivateKey privateKey;
	private PublicKey publicKey;

	private static boolean isExtensionActive() {
		return burp.BurpExtender.api != null && !burp.BurpExtender.unloading;
	}

	@Getter
	private final String correlationId;
	private final String secretKey;
	private final String pubKeyBase64;

	private String host;
	private int port;
	private boolean scheme;
	@Getter
	private volatile boolean registered;
	private String authorization;
	private String aesMode;

	public InteractshClient() {
		this.correlationId = UUID.randomUUID().toString().replace("-", "").substring(0, 20);
		this.secretKey = UUID.randomUUID().toString();

		KeyPair kp = generateKeys();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		this.pubKeyBase64 = Base64.getEncoder().encodeToString(getPublicKey().getBytes(StandardCharsets.UTF_8));

		this.host = burp.gui.Config.getHost();
		this.scheme = burp.gui.Config.getScheme();
		this.authorization = burp.gui.Config.getAuth();
		this.aesMode = burp.gui.Config.getAesMode();
		try {
			this.port = Integer.parseInt(burp.gui.Config.getPort());
		} catch (NumberFormatException ne) {
			this.port = 443;
		}
	}

	public boolean register() {
		if (!isExtensionActive())
			return false;

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
			burp.BurpExtender.debugLog("Sending registration request to " + host + ":" + port + " (TLS=" + scheme + ")");
			HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();
			burp.BurpExtender.debugLog("Registration response received: " + (resp != null ? resp.statusCode() : "null"));

			if (resp == null) {
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError(
							"Registration failed: No response received from server. Check your connection/host settings.");
				}
				return false;
			}

			if (resp.statusCode() == 200) {
				this.registered = true;
				burp.BurpExtender.debugLog("Session registration was successful.");
				return true;
			} else {
				if (isExtensionActive()) {
					burp.BurpExtender.api.logging().logToError(
							"Registration failed with status " + resp.statusCode() + ": " + resp.bodyToString());
				}
			}
		} catch (Exception ex) {
			if (isExtensionActive()) {
				String msg = (ex.getMessage() != null && ex.getMessage().contains("UnknownHostException"))
						? "Registration failed - the host '" + host + "' could not be resolved."
						: "Registration error: " + ex.getMessage();
				burp.BurpExtender.api.logging().logToError(msg);
			}
		}
		return false;
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

		HttpService httpService = HttpService.httpService(host, port, scheme);
		HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
		HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();
		if (resp == null || resp.statusCode() != 200) {
			if (isExtensionActive()) {
				burp.BurpExtender.api.logging().logToError("Poll failed - status: "
						+ (resp != null ? resp.statusCode() : "no response"));
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
					if (isExtensionActive()) {
						InteractshEntry entry = new InteractshEntry(decryptedData);
						burp.BurpExtender.addToTable(entry);
					}
				}
			}
		} catch (Exception ex) {
			if (isExtensionActive()) {
				String msg = (ex.getMessage() != null && ex.getMessage().contains("UnknownHostException"))
						? "Polling failed - the host '" + host + "' could not be resolved."
						: "Polling error: " + ex.getMessage();
				burp.BurpExtender.api.logging().logToError(msg);
			}
		}
		return true;
	}

	public void deregister() {
		if (!isExtensionActive())
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
			burp.BurpExtender.api.http().sendRequest(httpRequest).response();
		} catch (Exception ex) {
			if (isExtensionActive()) {
				String msg = (ex.getMessage() != null && ex.getMessage().contains("UnknownHostException"))
						? "Deregister failed - the host '" + host + "' could not be resolved."
						: "Deregister error: " + ex.getMessage();
				burp.BurpExtender.api.logging().logToError(msg);
			}
		}
	}

	public String getInteractDomain() {
		if (correlationId == null || correlationId.isEmpty()) {
			return "";
		} else {
			String fullDomain = correlationId;

			Random random = new Random();
			while (fullDomain.length() < 33) {
				fullDomain += (char) (random.nextInt(26) + 'a');
			}

			fullDomain += "." + host;
			return fullDomain;
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
