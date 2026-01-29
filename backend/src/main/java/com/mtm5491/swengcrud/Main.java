package main.java.com.mtm5491.swengcrud;

// Entry point for SWENG 861 CRUD project
// NEED TO RUN FROM CMD --> SRC FOLDER
// javac main/java/com/mtm5491/swengcrud/Main.java
// java main.java.com.mtm5491.swengcrud.Main

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
        // System.out.println("CLIENT ID = " + System.getenv("GOOGLE_CLIENT_ID"));
        // System.out.println("CLIENT SECRET = " + System.getenv("GOOGLE_CLIENT_SECRET"));
         
        // Server setup - Starts the server on port 8080. server will be: http://localhost:8080
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 8080), 0);
        //Define endpoint. When someone visits /health, they will recieve "Status: OK"
        server.createContext("/health", new JsonHandler("{\"status\": \"ok\"}"));
        
        // /api/hello endpoint
        server.createContext("/api/hello", new HelloHandler());

        // login and callback sessions
        server.createContext("/auth/login", new LoginHandler());
        server.createContext("/auth/callback", new CallbackHandler());
        
        // Protected endpoint
        server.createContext("/api/protected", new ProtectedHandler());
        
        server.setExecutor(null);
        server.start();
        System.out.println("Server running on http://localhost:8080");
    }


    /**
     * /auth/login handlers: exchange code for tokens, validate, create local session.
     * Start login: redirect to google.
     */
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // make sure Client ID is working
            String clientId = System.getenv("GOOGLE_CLIENT_ID");
            System.out.println("CLIENT ID BEING USED: " + clientId);

            String redirectUri = URLEncoder.encode("http://localhost:8080/auth/callback", StandardCharsets.UTF_8);
            String scope = URLEncoder.encode("openid email profile", StandardCharsets.UTF_8);
            // Generate random state value
            String state = UUID.randomUUID().toString(); 

            // Build google authorization URL
            String url = "https://accounts.google.com/o/oauth2/v2/auth"
                    + "?client_id=" + clientId
                    + "&redirect_uri=" + redirectUri
                    + "&response_type=code"
                    + "&scope=" + scope
                    + "&state=" + state;

            // Redirect user to Google login
            exchange.getResponseHeaders().add("Location", url);
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        }
    }

    /**
     * Redirects user to frontend with session cookie after successful login.
     */
    static class CallbackHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            /**
             *query string from callback URL  
             * URL will look something like auth/callback?code=4/0AY0e-g7...&state=xyz and getQuery() 
             * will return the part after the ?
             */ 
            String query = exchange.getRequestURI().getQuery();

            // parse params to extract code ands state
            Map<String, String> params = parseQuery(query);
            String code = params.get("code");
            String state = params.get("state");
            System.out.println("Callback received: code=" + code + ", state=" + state);

            // Error message for null code
            if (code == null) {
                sendText(exchange, 400, "Missing code");
                return;
            }

            // Build POST request to Google's token endpoint --> Must match what was used in auth/login
            String tokenEndpoint = "https://oauth2.googleapis.com/token";
            String clientId = System.getenv("GOOGLE_CLIENT_ID");
            String clientSecret = System.getenv("GOOGLE_CLIENT_SECRET");
            String redirectUri = "http://localhost:8080/auth/callback";
            
            // construct POST body
            String body = "code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                    + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                    + "&grant_type=authorization_code";

            // Send POST request to google
            // Open connection, set it to POST, send encoded body
            URL url = new URL(tokenEndpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            // read google's response token
            String responseJson;
            try (InputStream is = conn.getInputStream()) {
                responseJson = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
            System.out.println("Token response: " + responseJson);

            // JSON parse for id_token
            String idToken = extractJsonField(responseJson, "id_token");
            if (idToken == null) {
                sendText(exchange, 500, "No id_token in response");
                return;
            }

            // Decode ID Token
            String[] parts = idToken.split("\\.");
            if (parts.length < 2) {
                sendText(exchange, 500, "Invalid id_token format");
                return;
            }
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            System.out.println("ID Token payload: " + payloadJson);

            // Extract user identity fields 
            String sub = extractJsonField(payloadJson, "sub");  // User ID
            String email = extractJsonField(payloadJson, "email");  // User email
            String iss = extractJsonField(payloadJson, "iss");  // must be Google
            String aud = extractJsonField(payloadJson, "aud");  // must match client_ID

            // Minimal validation 
            if (iss == null || !iss.contains("accounts.google.com")) {
                System.out.println("Invalid issuer: " + iss);
            }
            if (aud == null || !aud.equals(clientId)) {
                System.out.println("Invalid audience: " + aud);
            }

            // Create or update the local user
            // if the user doesn't exist, create a new one; otherwise, update the existing user
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

            // Create sesssion and set a cookie
            String sessionId = UUID.randomUUID().toString();
            SessionStore.sessionsById.put(sessionId, user);
            exchange.getResponseHeaders().add("Set-Cookie", "sessionId=" + sessionId + "; HttpOnly; Path=/");

            // Shows successful login message
            String response = "Login successful. You can close this window.";
            sendText(exchange, 200, response);
        }
    }

static class HelloHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // CORS preflight
        // required for frontend to call backend
        // Was running into issues here so the Access-Control-Allow-Origin portion was added
        if (exchange.getRequestMethod().equalsIgnoreCase("OPTIONS")) {
            // exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Authorization");
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

        // checks that there is a session cookie and it maps to a valid user. Otherwise, 401 error
        User user = requireAuth(exchange);
        if (user == null) return; // requireAuth already sent 401

        // user email
        String email = (user.email != null) ? user.email : "user";

        // JSON response
        String json = "{ \"message\": \"Hello, " + email + "!\" }";
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        sendText(exchange, 200, json);
    }
}

    // helper class
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

    /**
     * Authentication middleware
     */
    static class ProtectedHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            if (method.equalsIgnoreCase("OPTIONS")) {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, OPTIONS");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Authorization");
                exchange.sendResponseHeaders(204, -1);
                return;
            }

        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

        
        User user = requireAuth(exchange);
        if (user == null) return; // middleware already sent 401

        // Protected response
        String json = "{ \"message\": \"You accessed a protected endpoint!\", \"email\": \"" +
                (user.email != null ? user.email : "") + "\" }";

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        sendText(exchange, 200, json);

        }
    }

    // Helper method --> send JSON response from handlers. 
    private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
        // convert to byte array
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        // sends HTTP status code
        exchange.sendResponseHeaders(status, bytes.length);
        // opens response stream, writes bytes
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


    // Parse quert into Map and returns
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

    //
    static User requireAuth(HttpExchange exchange) throws IOException {
        // gets cookie header from request
        String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");
        // error message if cookie null
        if (cookieHeader == null || !cookieHeader.contains("sessionId=")) {
            sendUnauthorized(exchange);
            return null;
        }
        String sessionId = null;
        // extract session ID from cookie
        for (String c : cookieHeader.split(";")) {
            c = c.trim();
            if (c.startsWith("sessionId=")) {
                sessionId = c.substring("sessionId=".length());
                break;
            }
        }
        // if null, send unauthorized
        if (sessionId == null) {
            sendUnauthorized(exchange);
            return null;
        }
        // look up user by session ID
        User user = SessionStore.sessionsById.get(sessionId);
        // if null, send unauthorized
        if (user == null) {
            sendUnauthorized(exchange);
            return null;
        }
        return user;
    }

    // Helper method to send 401 Unauthorized response
    static void sendUnauthorized(HttpExchange exchange) throws IOException {
        String json = "{ \"error\": \"Unauthorized\" }";
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(401, json.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(json.getBytes());
        }
    }
}




