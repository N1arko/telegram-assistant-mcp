# Start here: Telegram Assistant MCP

**English | [Русский](START-HERE.ru.md)**

Send this guide to your AI agent so it can help set everything up and explain each step to you.

## What you’ll need

- A Telegram account you want to connect.
- Your own server/VPS that stays available. Your AI agent needs secure access to it.
- A ChatGPT account where you’re allowed to add a custom MCP server. Availability depends on your plan, region, and workspace settings. Check your account and the [official OpenAI help article](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt).
- An AI agent that can work with code and your server.
- A public server address with HTTPS. You’ll usually need a domain or subdomain. A separate domain may not be needed if your hosting provider already gives you a suitable HTTPS address.
- An OAuth provider for sign-in. This project’s detailed example uses Auth0, so you need an Auth0 account if you follow that example. Another provider is suitable only if your agent verifies that it works with this server.

A VPS, domain, or OAuth provider may cost money. Check prices before signing up. ChatGPT and Telegram may also have limits.

## Setup in six steps

1. Send your agent the task below and a link to this guide.
2. Your agent checks access to your server and prepares the installation, settings, HTTPS, and MCP connection. It explains where you need to sign in or approve something.
3. You sign in to Telegram yourself. Enter any Telegram login code or two-step verification password only in a protected field or a hidden local terminal prompt. Never send it in your chat with the agent.
4. You sign in to ChatGPT and your OAuth provider, approve the requested permissions, and add the server after your agent shows you the address and steps.
5. With your agent, make one safe read-only check. It must not send messages or change their read status.
6. Ask your agent where the server runs, what it may cost, and how to manage it. It will be available while your VPS and the service are running.

Your agent can prepare the server and configuration files, but you handle sign-ins, codes, passwords, and consent. You don’t need programming skills or to retype long commands. Ask the agent to explain each step and carry out technical work through the tools available to it.

## Task for your AI agent

> Help me set up this project on my VPS and connect it to ChatGPT as a personal, read-only Telegram MCP. I’m not a developer: briefly explain what you’re doing and when you need me to sign in or approve something. Follow the [detailed agent setup guide](GETTING-STARTED.en.md). First check whether custom MCP is available in my ChatGPT account and what costs may apply. Don’t ask me to copy long commands by hand.
>
> Work in read-only mode only. Never print or commit secrets, tokens, Telegram session files, or login codes. Don’t ask me to send them in chat; direct me to protected fields or hidden local prompts. Don’t send Telegram messages or mark them read, even for testing. Don’t promise access to every channel; some channels may be unavailable. Don’t stop a running server without my separate consent. Before any expenses, access changes, or server changes, explain what’s needed and wait for my decision.
>
> Technical sections: [Telegram sign-in](GETTING-STARTED.en.md#2-create-a-separate-telegram-session), [OAuth/Auth0](GETTING-STARTED.en.md#3-configure-the-oauth-api-in-auth0), [ChatGPT connection](GETTING-STARTED.en.md#4-connect-chatgpt), [Docker and HTTPS](GETTING-STARTED.en.md#6-docker-and-tls), [first check](GETTING-STARTED.en.md#7-first-call-and-cooldown).
