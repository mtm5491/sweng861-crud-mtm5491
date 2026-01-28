package main.java.com.mtm5491.swengcrud;

// Entry point for SWENG 861 CRUD project

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

// HTTP server tools
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Main {

    // user fields
    static class User {
        String id;          // local user id
        String providerId;  // sub from Google
        String email;
        Instant createdAt;
        Instant updatedAt;
    }

    // stores users by providerID
     static class UserStore {
        static Map<String, User> usersByProviderId = new HashMap<>();
    }

    // stores users by sessionID
    static class SessionStore {
        static Map<String, User> sessionsById = new HashMap<>();
    }

    
    public static void main(String[] args) throws Exception {
        // Starts the server on port 8080. server will be: http://localhost:8080
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 8080), 0);
        //Define endpoint. When someone visits /health, they will recieve "Status: OK"
        server.createContext("/health", new JsonHandler("{\"status\": \"ok\"}"));
        // /api/hello endpoint
        server.createContext("/api/hello", new HelloHandler());

        // Register your OAuth endpoints
        server.createContext("/auth/login", new LoginHandler());
        server.createContext("/auth/callback", new CallbackHandler());
        // Protected endpoint
        server.createContext("/api/protected", new ProtectedHandler());
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server running on http://localhost:8080");
    }


    // Start login: redirect to google.
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String clientId = System.getenv("GOOGLE_CLIENT_ID");
            String redirectUri = URLEncoder.encode("http://localhost:8080/auth/callback", StandardCharsets.UTF_8);
            String scope = URLEncoder.encode("openid email profile", StandardCharsets.UTF_8);
            String state = UUID.randomUUID().toString(); 

            String url = "https://accounts.google.com/o/oauth2/v2/auth"
                    + "?client_id=" + clientId
                    + "&redirect_uri=" + redirectUri
                    + "&response_type=code"
                    + "&scope=" + scope
                    + "&state=" + state;

            exchange.getResponseHeaders().add("Location", url);
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        }
    }

    static class CallbackHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            Map<String, String> params = parseQuery(query);
            String code = params.get("code");
            String state = params.get("state");
            System.out.println("Callback received: code=" + code + ", state=" + state);

            if (code == null) {
                sendText(exchange, 400, "Missing code");
                return;
            }

            // Exchange code for tokens
            String tokenEndpoint = "https://oauth2.googleapis.com/token";
            String clientId = System.getenv("GOOGLE_CLIENT_ID");
            String clientSecret = System.getenv("GOOGLE_CLIENT_SECRET");
            String redirectUri = "http://localhost:8080/auth/callback";

            String body = "code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                    + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                    + "&grant_type=authorization_code";

            URL url = new URL(tokenEndpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            String responseJson;
            try (InputStream is = conn.getInputStream()) {
                responseJson = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            System.out.println("Token response: " + responseJson);

            // Very simple JSON parsing (for id_token only)
            String idToken = extractJsonField(responseJson, "id_token");
            if (idToken == null) {
                sendText(exchange, 500, "No id_token in response");
                return;
            }

            // 3. Token Validation & User Profile (simplified: decode payload, check iss/aud)
            String[] parts = idToken.split("\\.");
            if (parts.length < 2) {
                sendText(exchange, 500, "Invalid id_token format");
                return;
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            System.out.println("ID Token payload: " + payloadJson);

            String sub = extractJsonField(payloadJson, "sub");
            String email = extractJsonField(payloadJson, "email");
            String iss = extractJsonField(payloadJson, "iss");
            String aud = extractJsonField(payloadJson, "aud");

            // Minimal validation (for assignment): issuer + audience
            if (iss == null || !iss.contains("accounts.google.com")) {
                System.out.println("Invalid issuer: " + iss);
            }
            if (aud == null || !aud.equals(clientId)) {
                System.out.println("Invalid audience: " + aud);
            }

            // 4. Local Session / App Token: create/update local user, issue session cookie
            User user = UserStore.usersByProviderId.get(sub);
            if (user == null) {
                user = new User();
                user.id = UUID.randomUUID().toString();
                user.providerId = sub;
                user.email = email;
                user.createdAt = Instant.now();
                user.updatedAt = Instant.now();
                UserStore.usersByProviderId.put(sub, user);
                System.out.println("Created new user: " + user.id + " (" + email + ")");
            } else {
                user.updatedAt = Instant.now();
                System.out.println("Updated existing user: " + user.id + " (" + email + ")");
            }

            String sessionId = UUID.randomUUID().toString();
            SessionStore.sessionsById.put(sessionId, user);
            exchange.getResponseHeaders().add("Set-Cookie", "sessionId=" + sessionId + "; HttpOnly; Path=/");

            String response = "Login successful. You can close this window.";
            sendText(exchange, 200, response);
        }
    }

static class HelloHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // CORS preflight
        if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Authorization");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

        // ⭐ Authentication middleware
        User user = requireAuth(exchange);
        if (user == null) return; // requireAuth already sent 401

        String email = (user.email != null) ? user.email : "user";

        String json = "{ \"message\": \"Hello, " + email + "!\" }";
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        sendText(exchange, 200, json);
    }
}


    static class JsonHandler implements HttpHandler {
        private final String response;
        public JsonHandler(String response) {
            this.response = response;
        }
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    // Protected endpoint handler
    static class ProtectedHandler implements HttpHandler {
        @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();

        // CORS preflight
        if (method.equalsIgnoreCase("OPTIONS")) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Authorization");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

        // ⭐ NEW: use your middleware
        User user = requireAuth(exchange);
        if (user == null) return; // middleware already sent 401

        // Protected response
        String json = "{ \"message\": \"You accessed a protected endpoint!\", \"email\": \"" +
                (user.email != null ? user.email : "") + "\" }";

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        sendText(exchange, 200, json);

        }
    }

    private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

     // Very naive JSON field extractor: assumes "field":"value" with no nested quotes
    private static String extractJsonField(String json, String field) {
        String pattern = "\"" + field + "\"";
        int idx = json.indexOf(pattern);
        if (idx == -1) return null;
        int colon = json.indexOf(":", idx);
        if (colon == -1) return null;
        int startQuote = json.indexOf("\"", colon + 1);
        if (startQuote == -1) return null;
        int endQuote = json.indexOf("\"", startQuote + 1);
        if (endQuote == -1) return null;
        return json.substring(startQuote + 1, endQuote);
    }



    public static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null || query.isEmpty()) return result;

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2) {
                String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
                result.put(key, value);
            }
        }
        return result;
    }

    static User requireAuth(HttpExchange exchange) throws IOException {
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookieHeader == null || !cookieHeader.contains("sessionId=")) {
            sendUnauthorized(exchange);
            return null;
        }
        String sessionId = null;
        for (String c : cookieHeader.split(";")) {
            c = c.trim();
            if (c.startsWith("sessionId=")) {
                sessionId = c.substring("sessionId=".length());
                break;
            }
        }
        if (sessionId == null) {
            sendUnauthorized(exchange);
            return null;
        }
        User user = SessionStore.sessionsById.get(sessionId);
        if (user == null) {
            sendUnauthorized(exchange);
            return null;
        }
        return user;
    }

    static void sendUnauthorized(HttpExchange exchange) throws IOException {
    String json = "{ \"error\": \"Unauthorized\" }";
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(401, json.length());
    try (OutputStream os = exchange.getResponseBody()) {
        os.write(json.getBytes());
    }
}

}




