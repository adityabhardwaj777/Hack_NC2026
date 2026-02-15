# SecureBank AI Finance Chatbot

The AI chatbot provides real-time stock and crypto market data plus intelligent answers to finance questions using:

- **Yahoo Finance** (via RapidAPI) – stock quotes and market data  
- **CoinGecko** – cryptocurrency prices and 24h change  
- **Google Gemini** – AI-generated answers with market context  

## Setup

1. **Copy the environment template:**
   ```bash
   cp .env.example .env
   ```

2. **Add your API keys to `.env`:**

   | Key | Where to get it |
   |-----|-----------------|
   | `RAPIDAPI_KEY` | [RapidAPI Yahoo Finance](https://rapidapi.com/apidojo/api/yahoo-finance1) – subscribe to the free tier |
   | `COINGECKO_API_KEY` | [CoinGecko API](https://www.coingecko.com/en/api/pricing) – Demo plan (optional, improves rate limits) |
   | `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/apikey) – **required** for AI responses |

3. **Install dependencies** (if not already done):
   ```bash
   npm install
   ```
   If `npm install` fails on sqlite3, you can still run the server; the chatbot only needs `dotenv` (pure JS). Install it with:
   ```bash
   npm install dotenv
   ```

4. **Start the server:**
   ```bash
   npm start
   ```

5. **Open the chatbot:**
   - From the main SecureBank app: click **AI Assistant** in the nav
   - Or go to: `http://localhost:3000/chatbot.html`

## Usage

- **Stock prices** – e.g. “What’s the price of AAPL?” or “How is MSFT doing?”
- **Crypto prices** – e.g. “What’s Bitcoin and Ethereum trading at?”
- **Finance questions** – e.g. “How should I start investing?” or “Explain compound interest”

The chatbot infers stock tickers and crypto names from your message and pulls real-time data when available.
## something