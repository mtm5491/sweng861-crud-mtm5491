# SWENG 861 - Software Construction

**Name:** Madison (Maddie) Maynard

**Course Name:** SWENG 861 - Software Construction

**Description:** SWENG 861 weekly assignments

**Contact:"** email: mtm5491@psu.edu

**Week 2 Assignment**

**PART A - Authentication**
**Authentication Strategy:** I chose option B as an authentication strategy, specifically through Firebase Auth. This tool allows multiple forms of login and requires minimal frontend and backend setup. It also provides a token-based authentication which enhances security.

**Authentication Flow** The user clicks "Log in" or "Log in with Google" depending on their login preference. The user is redirected to google, chooses their account, and is presented with a successful or unsuccessful login message. Behind the scenes, Firebase passes an id token to the frontend, which sends it t o the backend in an authorization header. The backend verifies the token before allowing access.

**Step Sequence:** Client --> Login button --> IdP (Firebase) --> Frontend --> Backend --> Token --> Protected API

**PART B - Protected endpoint**
**Protected Endpoint Description:** I secured /api/hello which returns a "hello" greeting with the user's email. This is protected by the requireAuth class that acts as middleware; when api/hello is called, requireAuth checks for a valid cookie and verifies that the user is authenticated. If they are not, it returns a 401 Unathorized response.


**Part C - OWASP API Security Practices:** 
Avoid BOLA --> all protected endpoints rely on authenticated user extracted from session cookies that have been validated, ensuring users can only access their information.
Avoid Excessive Data Exposure --> responses are minimal and only return required information.
Avoid Security Misconfigurations --> no stack traces returned in client responses, only on server side.