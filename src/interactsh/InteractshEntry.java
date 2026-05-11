package interactsh;

import java.time.Instant;

import org.json.JSONException;
import org.json.JSONObject;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import interactsh.formatters.FormatterRegistry;
import lombok.Getter;
import lombok.Setter;

public class InteractshEntry {
	public String protocol;
	public String uid;
	public String details;
	public String rawRequest;
	public String rawResponse;
	public String address;
	public Instant timestamp;

	@Getter
	@Setter
	private boolean read = false;

	public final HttpRequest httpRequest;
	public final HttpResponse httpResponse;

	public InteractshEntry(String event) throws JSONException {
		JSONObject jsonObject = new JSONObject(event);
		this.protocol = jsonObject.getString("protocol");
		this.uid = jsonObject.getString("unique-id");
		this.address = jsonObject.getString("remote-address");
		this.timestamp = Instant.parse(jsonObject.getString("timestamp"));
		this.rawRequest = jsonObject.optString("raw-request", "");
		this.rawResponse = jsonObject.optString("raw-response", "");

		if (this.protocol.equals("http") || this.protocol.equals("https")) {
			this.httpRequest = HttpRequest.httpRequest(rawRequest);
			this.httpResponse = HttpResponse.httpResponse(rawResponse);
			this.details = (this.httpRequest == null) ? formatDetails(jsonObject) : "";
		} else {
			this.httpRequest = null;
			this.httpResponse = null;
			this.details = formatDetails(jsonObject);
		}
	}

	private String formatDetails(JSONObject obj) {
		try {
			return FormatterRegistry.get(protocol).format(obj);
		} catch (Exception e) {
			return "Error formatting interaction:\n" + e.getMessage() + "\n\nRaw data:\n" + obj.toString(2);
		}
	}

	public String toString() {
		return "Protocol: " + protocol + "\n" + "UID: " + uid + "\n" + "Address: " + address + "\n"
				+ "Timestamp: " + timestamp + "\n";
	}
}
