# Google Authentication Demo

A simple web application demonstrating Google OAuth authentication using Express.js.

## Features

- Google OAuth 2.0 Authentication
- User profile display after successful authentication
- Session management
- Clean and responsive UI

## Technologies Used

- Node.js
- Express.js
- Google Auth Library
- EJS Templating
- Express Session for session management
- Dotenv for environment variables

## Prerequisites

- Node.js installed on your machine
- A Google Cloud Platform account
- Google OAuth credentials (Client ID and Client Secret)

## Setup Instructions

1. Clone the repository
   ```
   git clone <repository-url>
   cd Google-Auth
   ```

2. Install dependencies
   ```
   npm install
   ```

3. Create a `.env` file in the root directory with the following variables:
   ```
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback
   SESSION_SECRET=your_session_secret
   ```

4. To get Google OAuth credentials:
   - Go to the [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one
   - Go to "APIs & Services" > "Credentials"
   - Create an OAuth client ID for a web application
   - Add `http://localhost:3000/auth/google/callback` as an authorized redirect URI

## Running the Application

1. Start the server:
   ```
   node index.js
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## How It Works

1. Users are presented with a login page
2. Clicking the "Sign in with Google" button redirects to Google's authentication page
3. After successful authentication, Google redirects back to the application
4. The application verifies the authentication and displays the user's profile information

## Directory Structure

- `index.js` - Main application file with route handlers
- `views/` - EJS templates for the UI
  - `index.ejs` - Login page
  - `profile.ejs` - User profile page after login
- `public/` - Static assets
  - `images/` - Images including Google logo

## License

ISC
