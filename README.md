# SWENG 861 - Software Construction

**Name:** Madison (Maddie) Maynard

**Course Name:** SWENG 861 - Software Construction

**Description:** SWENG 861 weekly assignments

**Contact:"** email: mtm5491@psu.edu

**Week 2**
**PART A**
**Authentication Strategy:** I chose option B as an authentication strategy, specifically through Firebase Auth. This tool allows multiple forms of login and requires minimal frontend and backend setup. It also provides a token-based authentication which enhances security.

**Authentication Flow** The user clicks "Log in" or "Log in with Google" depending on their login preference. The user is redirected to google, chooses their account, and is presented with a successful or unsuccessful login message. Behind the scenes, Firebase passes an id token to the frontend, which sends it t o the backend in an authorization header. The backend verifies the token before allowing access.

**Step Sequence:** Client --> Login button --> IdP (Firebase) --> Frontend --> Backend --> Token --> Protected API

**PART B**
**Protected Endpoint Description:** I secured /api/hello