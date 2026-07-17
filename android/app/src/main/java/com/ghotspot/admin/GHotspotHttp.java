package com.ghotspot.admin;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

final class GHotspotHttp {
    private GHotspotHttp() {
    }

    static JSONObject getJson(String url, Map<String, String> headers) throws Exception {
        return requestJson("GET", url, headers, null);
    }

    static JSONObject postJson(String url, Map<String, String> headers, JSONObject body) throws Exception {
        return requestJson("POST", url, headers, body == null ? new JSONObject() : body);
    }

    private static JSONObject requestJson(String method, String url, Map<String, String> headers, JSONObject body)
        throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(10000);
        connection.setRequestProperty("Accept", "application/json");
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                    connection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
        }
        if (body != null) {
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(bytes);
            }
        }

        int status = connection.getResponseCode();
        String response = readAll(status >= 400 ? connection.getErrorStream() : connection.getInputStream());
        if (status >= 400) {
            String message = response;
            try {
                JSONObject error = new JSONObject(response);
                message = error.optString("message", response);
            } catch (Exception ignored) {
            }
            throw new IOException(message);
        }
        return response == null || response.isEmpty() ? new JSONObject() : new JSONObject(response);
    }

    private static String readAll(InputStream input) throws IOException {
        if (input == null) return "";
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
        }
        return output.toString();
    }
}
